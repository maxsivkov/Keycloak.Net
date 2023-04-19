using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Flurl;
using Flurl.Http;
using Flurl.Http.Configuration;
using Keycloak.Net.Common.Extensions;
using Keycloak.Net.Models.Clients;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Keycloak.Net
{
    public partial class KeycloakClient
    {
        private ISerializer _serializer = new NewtonsoftJsonSerializer(new JsonSerializerSettings
        {
            ContractResolver = new CamelCasePropertyNamesContractResolver(),
            NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore,
            
        });

        protected internal readonly Url _url;
        protected internal readonly string _userName;
        protected internal readonly string _password;
        protected internal readonly string _clientSecret;
        protected internal readonly Func<string> _getToken;
        protected internal readonly KeycloakOptions _options;



        private readonly SemaphoreSlim _semaphore;
        private string? _access_token, _refresh_token;
        private int? _expires_in;
        private DateTime? _token_expiration;

        private KeycloakClient(string url, KeycloakOptions options)
        {
            _url = url;
            _options = options ?? new KeycloakOptions();
            _access_token = _refresh_token = null;
            _token_expiration = DateTime.Now;
            _expires_in = 60;
            _semaphore = new SemaphoreSlim(1, 1);
        }

        public KeycloakClient(string url, string userName, string password, KeycloakOptions options = null) 
            : this(url, options)
        {
            _userName = userName;
            _password = password;
        }

        public KeycloakClient(string url, string clientSecret, KeycloakOptions options = null)
            : this(url, options)
        {
            _clientSecret = clientSecret;
        }

        public KeycloakClient(string url, Func<string> getToken, KeycloakOptions options = null)
            : this(url, options)
        {
            _getToken = getToken;
        }

        public void SetSerializer(ISerializer serializer)
        {
            _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));
        }

        private dynamic TokenEndpoint(string url, string realm, IEnumerable<KeyValuePair<string, string>> data) => TokenEndpointAsync(url, realm, data).GetAwaiter().GetResult();

        private async Task<dynamic> TokenEndpointAsync(string url, string realm, IEnumerable<KeyValuePair<string, string>> data) =>
            await url
            .AppendPathSegment($"{_options.Prefix}/realms/{realm}/protocol/openid-connect/token")
            .WithHeader("Content-Type", "application/x-www-form-urlencoded")
            .WithHeader("Accept", "application/json")
            .PostUrlEncodedAsync(data)
            .ReceiveJson().ConfigureAwait(false);

        protected IEnumerable<KeyValuePair<string, string>> TokenEndpointData() =>
            _clientSecret != null ? new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_secret", _clientSecret),
                new KeyValuePair<string, string>("client_id", _options.AdminClientId)
            } : new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("username", _userName),
                new KeyValuePair<string, string>("password", _password),
                new KeyValuePair<string, string>("client_id", _options.AdminClientId)
            };
        protected async Task<string> RetrieveAccessTokenAsync(string authenticationRealm)
        {
            await _semaphore.WaitAsync();
            try
            {
                if (_expires_in is not null && DateTime.Now.AddSeconds(Convert.ToDouble(_expires_in) / 3) > _token_expiration)
                {
                    var data = _refresh_token is not null ? new List<KeyValuePair<string, string>>
                    {
                        new KeyValuePair<string, string>("grant_type", "refresh_token"),
                        new KeyValuePair<string, string>("client_id", _options?.AdminClientId),
                        new KeyValuePair<string, string>("refresh_token", _refresh_token)
                    } : TokenEndpointData();
                    //Trace.WriteLine($"{(_refresh_token is null ? "NEW" : "REFRESHED")} TOKEN RECEIVED");
                    var result = TokenEndpoint(_url, _options.AuthenticationRealmName ?? authenticationRealm, data);
                    _access_token = result.access_token.ToString();
                    _refresh_token = result.refresh_token.ToString();
                    _expires_in = Convert.ToInt32(result.expires_in.ToString());
                    _token_expiration = DateTime.Now.AddSeconds(Convert.ToDouble(_expires_in));
                }
            }
            finally
            {
                _semaphore.Release();
            }
            return _access_token;
        }

        protected string RetrieveAccessToken(string authenticationRealm) => RetrieveAccessTokenAsync(authenticationRealm).GetAwaiter().GetResult();

        public string GetAccessToken(string authenticationRealm) =>
            _getToken != null ? _getToken() : RetrieveAccessToken(authenticationRealm);
        private IFlurlRequest GetBaseUrl(string authenticationRealm) => new Url(_url)
            .AppendPathSegment(_options.Prefix)
            .ConfigureRequest(settings => settings.JsonSerializer = _serializer)
            .WithAuthentication(authenticationRealm, this);
    }

    public class KeycloakOptions
    {
        public string Prefix { get; set; }
        public string AdminClientId { get; set; }
        public string AuthenticationRealmName { get; set; }

        public KeycloakOptions(string prefix = "", string adminClientId = "admin-cli", string authenticationRealmName = null)
        {
            Prefix = prefix.TrimStart('/').TrimEnd('/');
            AdminClientId = adminClientId;
            AuthenticationRealmName = authenticationRealmName;
        }
        public KeycloakOptions()
        {
            Prefix = "";
            AdminClientId = "admin-cli";
            AuthenticationRealmName = null;
        }

    }
}