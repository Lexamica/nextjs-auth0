import { Issuer, custom, HttpOptions, Client, EndSessionParameters } from 'openid-client';
import url, { UrlObject } from 'url';
import urlJoin from 'url-join';
import createDebug from './utils/debug';
import { Config } from './config';

const debug = createDebug('client');

export interface ClientFactory {
  (): Promise<Client>;
}

export type Telemetry = {
  name: string;
  version: string;
};

function sortSpaceDelimitedString(str: string): string {
  return str.split(' ').sort().join(' ');
}

// Issuer.discover throws an `AggregateError` in some cases, this error includes the stack trace in the
// message which causes the stack to be exposed when reporting the error in production. Am using the non standard
// `_errors` property to identify the polyfilled `AggregateError`
// See https://github.com/sindresorhus/aggregate-error/issues/4#issuecomment-488356468
function normalizeAggregateError(e: Error | (Error & { _errors: Error[] })): Error {
  if ('_errors' in e) {
    return e._errors[0];
  }
  return e;
}

export default function get(config: Config, { name, version }: Telemetry): ClientFactory {
  let client: Client | null = null;

  return async (): Promise<Client> => {
    if (client) {
      return client;
    }
    console.log('get client - client is null');
    const defaultHttpOptions = (options: HttpOptions): HttpOptions => ({
      ...options,
      headers: {
        ...options.headers,
        'User-Agent': `${name}/${version}`,
        ...(config.enableTelemetry
          ? {
              'Auth0-Client': Buffer.from(
                JSON.stringify({
                  name,
                  version,
                  env: {
                    node: process.version
                  }
                })
              ).toString('base64')
            }
          : undefined)
      },
      timeout: config.httpTimeout
    });
    console.log('get client - defaultHttpOptions');
    const applyHttpOptionsCustom = (entity: Issuer<Client> | typeof Issuer | Client): void => {
      // eslint-disable-next-line no-param-reassign
      entity[custom.http_options] = defaultHttpOptions;
    };
    console.log('get client - applyHttpOptionsCustom');

    applyHttpOptionsCustom(Issuer);
    let issuer: Issuer<Client>;
    try {
      issuer = await Issuer.discover(config.issuerBaseURL);
    } catch (e) {
      throw normalizeAggregateError(e);
    }
    console.log('get client - Issuer.discover', issuer);
    applyHttpOptionsCustom(issuer);
    console.log('get client - applyHttpOptionsCustom(issuer)');

    const issuerTokenAlgs = Array.isArray(issuer.id_token_signing_alg_values_supported)
      ? issuer.id_token_signing_alg_values_supported
      : [];
    if (!issuerTokenAlgs.includes(config.idTokenSigningAlg)) {
      debug(
        'ID token algorithm %o is not supported by the issuer. Supported ID token algorithms are: %o.',
        config.idTokenSigningAlg,
        issuerTokenAlgs
      );
    }
    console.log('get client - issuerTokenAlgs');

    const configRespType = sortSpaceDelimitedString(config.authorizationParams.response_type);
    console.log('get client - configRespType');
    const issuerRespTypes = Array.isArray(issuer.response_types_supported) ? issuer.response_types_supported : [];
    console.log('get client - issuerRespTypes');
    issuerRespTypes.map(sortSpaceDelimitedString);
    if (!issuerRespTypes.includes(configRespType)) {
      debug(
        'Response type %o is not supported by the issuer. Supported response types are: %o.',
        configRespType,
        issuerRespTypes
      );
    }
    console.log('get client - issuerRespTypes.includes(configRespType)');

    const configRespMode = config.authorizationParams.response_mode;
    const issuerRespModes = Array.isArray(issuer.response_modes_supported) ? issuer.response_modes_supported : [];
    if (configRespMode && !issuerRespModes.includes(configRespMode)) {
      debug(
        'Response mode %o is not supported by the issuer. Supported response modes are %o.',
        configRespMode,
        issuerRespModes
      );
    }
    console.log('get client - issuerRespModes.includes(configRespMode)');

    console.log('get client - create client config', config);
    client = new issuer.Client({
      client_id: config.clientID,
      client_secret: config.clientSecret,
      id_token_signed_response_alg: config.idTokenSigningAlg
    });
    console.log('get client - issuer.Client');
    applyHttpOptionsCustom(client);
    client[custom.clock_tolerance] = config.clockTolerance;
    console.log('get client - applyHttpOptionsCustom(client)');

    if (config.idpLogout) {
      console.log('get client - config.idpLogout');
      if (
        config.auth0Logout ||
        ((url.parse(issuer.metadata.issuer).hostname as string).match('\\.auth0\\.com$') &&
          config.auth0Logout !== false)
      ) {
        console.log('get client - config.auth0Logout');
        Object.defineProperty(client, 'endSessionUrl', {
          value(params: EndSessionParameters) {
            const parsedUrl = url.parse(urlJoin(issuer.metadata.issuer, '/v2/logout'));
            (parsedUrl as UrlObject).query = {
              returnTo: params.post_logout_redirect_uri,
              client_id: config.clientID
            };
            console.log('get client - parsedUrl', parsedUrl);
            return url.format(parsedUrl);
          }
        });
      } else if (!issuer.end_session_endpoint) {
        debug('the issuer does not support RP-Initiated Logout');
      }
    }
    console.log('get client - client', client);

    return client;
  };
}
