export class RetryableUpstreamError extends Error {
  constructor() {
    super('The nutrition service is temporarily unavailable. Please retry your request.');
    this.name = 'RetryableUpstreamError';
  }
}
