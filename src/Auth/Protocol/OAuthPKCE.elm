module Auth.Protocol.OAuthPKCE exposing (..)

import Auth.Common exposing (..)
import Auth.HttpHelpers as HttpHelpers
import Browser.Navigation as Navigation
import Bytes exposing (Endianness(..))
import Bytes.Encode
import Dict exposing (Dict)
import Hack
import Http
import Json.Decode as Json
import OAuth.AuthorizationCode as OAuth
import OAuth.AuthorizationCode.PKCE as PKCE
import Process
import SHA1
import Task exposing (Task)
import Time
import Types
import Url exposing (Url)


onFrontendCallbackInit :
    { frontendModel | authFlow : Flow, authRedirectBaseUrl : Url }
    -> Auth.Common.MethodId
    -> Url
    -> Navigation.Key
    -> (Auth.Common.ToBackend -> Cmd frontendMsg)
    -> ( { frontendModel | authFlow : Flow, authRedirectBaseUrl : Url }, Cmd frontendMsg )
onFrontendCallbackInit model methodId origin navigationKey toBackendFn =
    let
        redirectUri =
            { origin | query = Nothing, fragment = Nothing }

        clearUrl =
            Navigation.replaceUrl navigationKey (Url.toString model.authRedirectBaseUrl)
    in
    case OAuth.parseCode origin of
        OAuth.Empty ->
            let
                _ =
                    Debug.log "OAuth: No code found in URL" ()
            in
            ( { model | authFlow = Idle }
            , Cmd.none
            )

        OAuth.Success { code, state } ->
            let
                _ =
                    Debug.log "OAuth: Code found in URL" code

                state_ =
                    state |> Maybe.withDefault ""

                model_ =
                    { model | authFlow = Authorized code state_ }

                ( newModel, newCmds ) =
                    accessTokenRequested model_ methodId code state_
            in
            ( newModel
            , Cmd.batch [ toBackendFn newCmds, clearUrl ]
            )

        OAuth.Error error ->
            let
                _ =
                    Debug.log "OAuth: Error found in URL" error
            in
            ( { model | authFlow = Errored <| ErrAuthorization error }
            , clearUrl
            )


accessTokenRequested :
    { frontendModel | authFlow : Flow, authRedirectBaseUrl : Url }
    -> Auth.Common.MethodId
    -> OAuth.AuthorizationCode
    -> Auth.Common.State
    -> ( { frontendModel | authFlow : Flow, authRedirectBaseUrl : Url }, Auth.Common.ToBackend )
accessTokenRequested model methodId code state =
    ( { model | authFlow = Authorized code state }
    , AuthCallbackReceived methodId model.authRedirectBaseUrl code state
    )


initiateSignin : Bool -> String -> Url -> ConfigurationOAuthPKCE frontendMsg backendMsg frontendModel backendModel -> (BackendMsg -> a) -> Time.Posix -> { b | pendingAuths : Dict String PendingAuth } -> ( { b | pendingAuths : Dict String PendingAuth }, Cmd a )
initiateSignin isDev sessionId baseUrl config asBackendMsg now backendModel =
    let
        signedState =
            SHA1.toBase64 <|
                SHA1.fromString <|
                    (String.fromInt <| Time.posixToMillis <| now)
                        -- @TODO this needs to be user-injected config
                        ++ "0x3vd7a"
                        ++ sessionId

        newPendingAuth : PendingAuth
        newPendingAuth =
            { sessionId = sessionId
            , created = now
            , state = signedState
            }

        url =
            generateSigninUrl baseUrl signedState config
    in
    ( { backendModel
        | pendingAuths = backendModel.pendingAuths |> Dict.insert sessionId newPendingAuth
      }
    , Auth.Common.sleepTask
        isDev
        (asBackendMsg
            (AuthSigninInitiatedDelayed_
                sessionId
                (AuthInitiateSignin url)
            )
        )
    )


generateSigninUrl : Url -> Auth.Common.State -> Auth.Common.ConfigurationOAuthPKCE frontendMsg backendMsg frontendModel backendModel -> Url
generateSigninUrl baseUrl state configuration =
    let
        queryAdjustedUrl =
            -- google auth is an example where, at time of writing, query parameters are not allowed in a login redirect url
            if configuration.allowLoginQueryParameters then
                baseUrl

            else
                { baseUrl | query = Nothing }

        authorizationPkce : PKCE.Authorization
        authorizationPkce =
            { clientId = configuration.clientId
            , redirectUri = { queryAdjustedUrl | path = "/login/" ++ configuration.id ++ "/callback" }
            , scope = configuration.scope
            , state = Just state
            , url = configuration.authorizationEndpoint
            , codeChallenge = PKCE.mkCodeChallenge Hack.codeVerifier
            }
    in
    authorizationPkce
        |> PKCE.makeAuthorizationUrl


onAuthCallbackReceived :
    SessionId
    -> ClientId
    ->
        { a
            | clientId : String
            , clientSecret :
                String
            , tokenEndpoint : Url
            , id : MethodId
            , getUserInfo : PKCE.AuthenticationSuccess -> Task Error UserInfo
        }
    -> Url
    -> OAuth.AuthorizationCode
    -> f
    -> Time.Posix
    -> (BackendMsg -> c)
    -> { b | pendingAuths : Dict SessionId { d | state : f } }
    -> ( { b | pendingAuths : Dict SessionId { d | state : f } }, Cmd c )
onAuthCallbackReceived sessionId clientId method receivedUrl code state now asBackendMsg backendModel =
    ( backendModel
    , validateCallbackToken method.clientId method.clientSecret method.tokenEndpoint receivedUrl code
        |> Task.andThen
            (\authenticationResponse ->
                case backendModel.pendingAuths |> Dict.get sessionId of
                    Just pendingAuth ->
                        let
                            authToken =
                                Just (makeToken method.id authenticationResponse now)
                        in
                        if pendingAuth.state == state then
                            method.getUserInfo
                                authenticationResponse
                                |> Task.map (\userInfo -> ( userInfo, authToken ))

                        else
                            Task.fail <| Auth.Common.ErrAuthString "Invalid auth state. Please log in again or report this issue."

                    Nothing ->
                        Task.fail <| Auth.Common.ErrAuthString "Couldn't validate auth, please login again."
            )
        |> Task.attempt (Auth.Common.AuthSuccess sessionId clientId method.id now >> asBackendMsg)
    )


validateCallbackToken :
    String
    -> String
    -> Url
    -> Url
    -> OAuth.AuthorizationCode
    -> Task Auth.Common.Error PKCE.AuthenticationSuccess
validateCallbackToken clientId clientSecret tokenEndpoint redirectUri code =
    let
        auth : PKCE.Authentication
        auth =
            { credentials =
                { clientId = clientId
                , secret = Just clientSecret
                }
            , code = code
            , codeVerifier = Hack.codeVerifier
            , redirectUri =
                { redirectUri | query = Nothing, fragment = Nothing }
            , url =
                tokenEndpoint
            }

        req : PKCE.RequestParts ()
        req =
            PKCE.makeTokenRequest (always ()) auth
    in
    { method = req.method
    , headers = req.headers ++ [ Http.header "Accept" "application/json" ]
    , url = req.url
    , body = req.body
    , resolver = HttpHelpers.jsonResolver PKCE.defaultAuthenticationSuccessDecoder
    , timeout = req.timeout
    }
        |> Http.task
        |> Task.mapError parseAuthenticationResponseError


parseAuthenticationResponse : Result Http.Error OAuth.AuthenticationSuccess -> Result Auth.Common.Error OAuth.AuthenticationSuccess
parseAuthenticationResponse res =
    case res of
        Err (Http.BadBody body) ->
            case Json.decodeString OAuth.defaultAuthenticationErrorDecoder body of
                Ok error ->
                    Err <| Auth.Common.ErrAuthentication error

                _ ->
                    Err Auth.Common.ErrHTTPGetAccessToken

        Err _ ->
            Err Auth.Common.ErrHTTPGetAccessToken

        Ok authenticationSuccess ->
            Ok authenticationSuccess


parseAuthenticationResponseError : Http.Error -> Auth.Common.Error
parseAuthenticationResponseError httpErr =
    let
        _ =
            Debug.log "httpErr!! " httpErr
    in
    case httpErr of
        Http.BadBody body ->
            case Json.decodeString OAuth.defaultAuthenticationErrorDecoder body of
                Ok error ->
                    Auth.Common.ErrAuthentication error

                _ ->
                    Auth.Common.ErrHTTPGetAccessToken

        _ ->
            Auth.Common.ErrHTTPGetAccessToken


makeToken : Auth.Common.MethodId -> PKCE.AuthenticationSuccess -> Time.Posix -> Auth.Common.Token
makeToken methodId authenticationSuccess now =
    { methodId = methodId
    , token = authenticationSuccess.token
    , created = now
    , expires =
        (Time.posixToMillis now
            + ((authenticationSuccess.expiresIn |> Maybe.withDefault 0) * 1000)
        )
            |> Time.millisToPosix
    }
