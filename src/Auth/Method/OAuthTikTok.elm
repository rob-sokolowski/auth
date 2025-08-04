module Auth.Method.OAuthTikTok exposing (..)

import Auth.Common exposing (..)
import Auth.HttpHelpers as HttpHelpers
import Auth.Protocol.OAuth
import Base64.Encode as Base64
import Browser.Navigation as Navigation
import Bytes exposing (Bytes)
import Bytes.Encode as Bytes
import Http
import Json.Decode as Json
import Json.Decode.Pipeline exposing (..)
import List.Extra as List
import OAuth
import OAuth.AuthorizationCode.PKCE as PKCE
import Task exposing (Task)
import Url exposing (Protocol(..), Url)


configuration :
    String
    -> String
    ->
        Method
            frontendMsg
            backendMsg
            { frontendModel | authFlow : Flow, authRedirectBaseUrl : Url }
            backendModel
configuration clientId clientSecret =
    ProtocolOAuthPKCE
        { id = "OAuthTikTok"
        , authorizationEndpoint =
            { defaultHttpsUrl
                | host = "www.tiktok.com"
                , path = "/v2/auth/authorize"
                , query = Just "disable_auto_auth=1"
            }
        , tokenEndpoint =
            { defaultHttpsUrl
                | host = "open.tiktokapis.com"
                , path = "/v2/oauth/token/"
            }
        , logoutEndpoint = Home { returnPath = "/logout/OAuthTikTok/callback" }
        , allowLoginQueryParameters = False
        , clientId = clientId
        , clientSecret = clientSecret
        , scope =
            [ "user.info.basic"
            ]
        , getUserInfo = getUserInfo
        , onFrontendCallbackInit = Auth.Protocol.OAuth.onFrontendCallbackInit
        , placeholder = \_ -> ()
        }


getUserInfo :
    PKCE.AuthenticationSuccess
    -> Task Auth.Common.Error UserInfo
getUserInfo authenticationSuccess =
    getUserInfoTask authenticationSuccess
        |> Task.andThen
            (\userInfo ->
                if userInfo.email == "" then
                    fallbackGetEmailFromEmails authenticationSuccess userInfo

                else
                    Task.succeed userInfo
            )


fallbackGetEmailFromEmails : PKCE.AuthenticationSuccess -> UserInfo -> Task Auth.Common.Error UserInfo
fallbackGetEmailFromEmails authenticationSuccess userInfo =
    getUserEmailsTask authenticationSuccess
        |> Task.andThen
            (\userEmails ->
                case userEmails |> List.find (\v -> v.primary == True) of
                    Just record ->
                        Task.succeed { userInfo | email = record.email }

                    Nothing ->
                        Task.fail <|
                            HttpHelpers.customError
                                "Could not retrieve an email from Github profile or emails list."
            )
        |> Task.mapError (HttpHelpers.httpErrorToString >> Auth.Common.ErrAuthString)


getUserInfoTask : PKCE.AuthenticationSuccess -> Task Auth.Common.Error UserInfo
getUserInfoTask authenticationSuccess =
    Http.task
        { method = "GET"
        , headers = OAuth.useToken authenticationSuccess.token []
        , url =
            Url.toString
                { defaultHttpsUrl
                    | host = "open.tiktokapis.com"
                    , path = "/v2/user/info/"
                    , query = Just "fields=display_name"
                }
        , body = Http.emptyBody
        , resolver =
            HttpHelpers.jsonResolver
                (Json.at [ "data", "user" ]
                    (Json.succeed UserInfo
                        |> optional "display_name" Json.string ""
                        |> optional "name" decodeNonEmptyString Nothing
                        |> optional "login" decodeNonEmptyString Nothing
                    )
                )
        , timeout = Nothing
        }
        |> Task.mapError (HttpHelpers.httpErrorToString >> Auth.Common.ErrAuthString)


decodeNonEmptyString : Json.Decoder (Maybe String)
decodeNonEmptyString =
    Json.string |> Json.map nothingIfEmpty


type alias GithubEmail =
    { primary : Bool, email : String }


getUserEmailsTask : PKCE.AuthenticationSuccess -> Task Http.Error (List GithubEmail)
getUserEmailsTask authenticationSuccess =
    Http.task
        { method = "GET"
        , headers = OAuth.useToken authenticationSuccess.token []
        , url = Url.toString { defaultHttpsUrl | host = "api.github.com", path = "/user/emails" }
        , body = Http.emptyBody
        , resolver =
            HttpHelpers.jsonResolver
                (Json.list
                    (Json.map2 GithubEmail
                        (Json.field "primary" Json.bool)
                        (Json.field "email" Json.string)
                    )
                )
        , timeout = Nothing
        }
