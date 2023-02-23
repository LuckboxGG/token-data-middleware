declare module '@luckbox/token-data-middleware' {
  export type TokenParts = {
    signature: string;
    payload: string;
  };

  export type TokenParser = (token: string) => Record<string, unknown>;
  export type AsyncTokenParser = (token: string) => Promise<Record<string, unknown>>;

  /**
   * Initializes a new token parser
   * @param {String|Buffer} publicKey PEM-formatted public key
   * @return {TokenParser} Token parser function
   */
  export function parser(publicKey: string | Buffer): TokenParser;

  /**
   * Initializes a new async token parser
   * @param {String|Buffer} publicKey PEM-formatted public key
   * @return {AsyncTokenParser} Token parser function
   */
  export function asyncParser(publicKey: string | Buffer): AsyncTokenParser;


  /**
   * Splits a token to its payload and signature parts
   * @param {String} token
   * @return {TokenParts}
   */
  export function extractParts(token: string): TokenParts;

  /**
   * Creates an Express 4.x middleware that automatically parses signed tokens in request headers
   * @param {String} publicKey PEM-formatted public key
   * @param {String} headerName Name of the request header
   * @return {Function} Express 4.x middleware
   */
  export function tokenData(publicKey: string, headerName: string): (req: unknown, res: unknown, next: () => void) => void;

  /**
   * Generates a token from a payload
   * @param {*} data
   * @param {String|Buffer} privateKey
   * @return {String}
   */
  export function sign(data: unknown, privateKey: string | Buffer): string;
}
