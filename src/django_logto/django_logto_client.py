import time
import urllib
from typing import Optional

from asgiref.sync import sync_to_async
from logto import LogtoClient, LogtoConfig, Storage, LogtoException
from logto.LogtoClient import AccessTokenMap, AccessToken, SignInSession, InteractionMode
from logto.OidcCore import OidcCore
from logto.models.oidc import UserInfoScope, IdTokenClaims
from logto.models.response import TokenResponse, UserInfoResponse
from logto.utilities import removeFalsyKeys, OrganizationUrnPrefix


@sync_to_async
def validate_signin_session(signInSession):
    return SignInSession.model_validate_json(signInSession)


class DjangoLogtoClient(LogtoClient):
    def __init__(self, config: LogtoConfig, storage: Storage):
        super().__init__(config=config, storage=storage)

    async def _getAccessTokenMap(self) -> AccessTokenMap:
        """
        Get the access token map from storage.
        """
        accessTokenMap = await self._storage.get("accessTokenMap")
        try:
            return AccessTokenMap.model_validate_json(accessTokenMap)
        except:
            return AccessTokenMap(x={})

    async def _setAccessToken(self, resource: str, accessToken: str, expiresIn: int) -> None:
        """
        Set the access token for the given resource to storage.
        """
        accessTokenMap = await self._getAccessTokenMap()
        accessTokenMap.x[resource] = AccessToken(
            token=accessToken,
            expiresAt=int(time.time())
                      + expiresIn
                      - 60,  # 60 seconds earlier to avoid clock skew
        )
        await self._storage.set("accessTokenMap", accessTokenMap.model_dump_json())

    async def getAccessToken(self, resource: str = "") -> Optional[str]:
        """
        Get the access token for the given resource. If the access token is expired,
        it will be refreshed automatically. If no refresh token is found, None will
        be returned.
        """
        accessToken = await self._getAccessToken(resource)
        if accessToken is not None:
            return accessToken

        if (
                resource.startswith(OrganizationUrnPrefix)
                and UserInfoScope.organizations not in self.config.scopes
        ):
            raise LogtoException(
                "The `UserInfoScope.organizations` scope is required to fetch organization tokens"
            )

        refreshToken = await self._storage.get("refreshToken")
        if refreshToken is None:
            return None

        tokenResponse = await (await self.getOidcCore()).fetchTokenByRefreshToken(
            clientId=self.config.appId,
            clientSecret=self.config.appSecret,
            refreshToken=refreshToken,
            resource=resource,
        )

        await self._handleTokenResponse(resource, tokenResponse)
        return tokenResponse.access_token

    async def _getAccessToken(self, resource: str) -> Optional[str]:
        """
        Get the valid access token for the given resource from storage, no refresh will be
        performed.
        """
        accessTokenMap = await self._getAccessTokenMap()
        accessToken = accessTokenMap.x.get(resource, None)
        if accessToken is None or accessToken.expiresAt < int(time.time()):
            return None
        return accessToken.token

    async def _handleTokenResponse(
            self, resource: str, tokenResponse: TokenResponse
    ) -> None:
        """
        Handle the token response from the Logto server and store the tokens to storage.

        Resource can be an empty string, which means the access token is for UserInfo
        endpoint or the default resource.
        """
        if tokenResponse.id_token is not None:
            (await self.getOidcCore()).verifyIdToken(
                tokenResponse.id_token, self.config.appId
            )
            await self._storage.set("idToken", tokenResponse.id_token)

        if tokenResponse.refresh_token is not None:
            await self._storage.set("refreshToken", tokenResponse.refresh_token)

        await self._setAccessToken(
            resource, tokenResponse.access_token, tokenResponse.expires_in
        )

    async def _getSignInSession(self) -> Optional[SignInSession]:
        """
        Try to parse the current sign-in session from storage. If the value does not
        exist or parse failed, return None.
        """
        signInSession = await self._storage.get("signInSession")
        if signInSession is None:
            return None

        try:
            session = await validate_signin_session(signInSession)
            return session
        except:
            return None

    async def _setSignInSession(self, signInSession: SignInSession) -> None:
        await self._storage.set("signInSession", signInSession.model_dump_json())

    async def signIn(
            self, redirectUri: str, interactionMode: Optional[InteractionMode] = None
    ) -> str:
        """
        Returns the sign-in URL for the given redirect URI. You should redirect the user
        to the returned URL to sign in.

        By specifying the interaction mode, you can control whether the user will be
        prompted for sign-in or sign-up on the first screen. If the interaction mode is
        not specified, the default one will be used.

        Example:
          ```python
          return redirect(await client.signIn('https://example.com/callback'))
          ```
        """
        codeVerifier = OidcCore.generateCodeVerifier()
        codeChallenge = OidcCore.generateCodeChallenge(codeVerifier)
        state = OidcCore.generateState()
        signInUrl = await self._buildSignInUrl(
            redirectUri, codeChallenge, state, interactionMode
        )

        await self._setSignInSession(
            SignInSession(
                redirectUri=redirectUri,
                codeVerifier=codeVerifier,
                state=state,
            )
        )
        for key in ["idToken", "accessToken", "refreshToken"]:
            await self._storage.delete(key)

        return signInUrl

    async def signOut(self, postLogoutRedirectUri: Optional[str] = None) -> str:
        """
        Returns the sign-out URL for the given post-logout redirect URI. You should
        redirect the user to the returned URL to sign out.

        If the post-logout redirect URI is not provided, the Logto default post-logout
        redirect URI will be used.

        Note:
          If the OpenID Connect server does not support the end session endpoint
          (i.e. OpenID Connect RP-Initiated Logout), the function will throw an
          exception. Logto supports the end session endpoint.

        Example:
          ```python
          return redirect(await client.signOut('https://example.com'))
          ```
        """
        await self._storage.delete("idToken")
        await self._storage.delete("refreshToken")
        await self._storage.delete("accessTokenMap")
        endSessionEndpoint = (await self.getOidcCore()).metadata.end_session_endpoint

        if endSessionEndpoint is None:
            raise LogtoException(
                "End session endpoint not found in the provider metadata"
            )

        return (
                endSessionEndpoint
                + "?"
                + urllib.parse.urlencode(
            removeFalsyKeys(
                {
                    "client_id": self.config.appId,
                    "post_logout_redirect_uri": postLogoutRedirectUri,
                }
            )
        )
        )

    async def handleSignInCallback(self, callbackUri: str) -> None:
        """
        Handle the sign-in callback from the Logto server. This method should be called
        in the callback route handler of your application.
        """
        signInSession = await self._getSignInSession()

        if signInSession is None:
            raise LogtoException("Sign-in session not found")

        # Validate the callback URI without query matches the redirect URI
        parsedCallbackUri = urllib.parse.urlparse(callbackUri)
        if (
                parsedCallbackUri.path
                != urllib.parse.urlparse(signInSession.redirectUri).path
        ):
            raise LogtoException(
                "The URI path does not match the redirect URI in the sign-in session"
            )

        query = urllib.parse.parse_qs(parsedCallbackUri.query)
        if "error" in query:
            raise LogtoException(query["error"][0])

        if signInSession.state != query.get("state", [None])[0]:
            raise LogtoException("Invalid state in the callback URI")

        code = query.get("code", [None])[0]
        if code is None:
            raise LogtoException("Code not found in the callback URI")

        tokenResponse = await (await self.getOidcCore()).fetchTokenByCode(
            clientId=self.config.appId,
            clientSecret=self.config.appSecret,
            redirectUri=signInSession.redirectUri,
            code=code,
            codeVerifier=signInSession.codeVerifier,
        )

        await self._handleTokenResponse("", tokenResponse)
        await self._storage.delete("signInSession")

    async def getIdToken(self) -> Optional[str]:
        """
        Get the ID Token string. If you need to get the claims in the ID Token, use
        `getIdTokenClaims` instead.
        """
        return await self._storage.get("idToken")

    async def getIdTokenClaims(self) -> IdTokenClaims:
        """
        Get the claims in the ID Token. If the ID Token does not exist, an exception
        will be thrown.
        """
        idToken = await self._storage.get("idToken")
        if idToken is None:
            raise LogtoException("ID Token not found")

        return OidcCore.decodeIdToken(idToken)

    async def getRefreshToken(self) -> Optional[str]:
        """
        Get the refresh token string.
        """
        return await self._storage.get("refreshToken")

    async def isAuthenticated(self) -> bool:
        """
        Check if the user is authenticated by checking if the ID Token exists.
        """
        return await self._storage.get("idToken") is not None

    async def fetchUserInfo(self) -> UserInfoResponse:
        """
        Fetch the user information from the UserInfo endpoint. If the access token
        is expired, it will be refreshed automatically.
        """
        accessToken = await self.getAccessToken()
        return await (await self.getOidcCore()).fetchUserInfo(accessToken)
