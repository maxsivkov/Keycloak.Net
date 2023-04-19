using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Flurl;
using Flurl.Http;

namespace Keycloak.Net.Common.Extensions
{
    public static class FlurlRequestExtensions
    {
        public static IFlurlRequest WithAuthentication(this IFlurlRequest request, string authenticationRealm, KeycloakClient cli)
             => request.WithOAuthBearerToken(cli.GetAccessToken(authenticationRealm));
        public static IFlurlRequest WithForwardedHttpHeaders(this IFlurlRequest request, ForwardedHttpHeaders forwardedHeaders)
        {
            if (!string.IsNullOrEmpty(forwardedHeaders?.forwardedFor))
            {
	            request = request.WithHeader("X-Forwarded-For", forwardedHeaders.forwardedFor);
            }

            if (!string.IsNullOrEmpty(forwardedHeaders?.forwardedProto))
            {
	            request = request.WithHeader("X-Forwarded-Proto", forwardedHeaders.forwardedProto);
            }

            if (!string.IsNullOrEmpty(forwardedHeaders?.forwardedHost))
            {
	            request = request.WithHeader("X-Forwarded-Host", forwardedHeaders.forwardedHost);
            }

            return request;
        }
    }
}
