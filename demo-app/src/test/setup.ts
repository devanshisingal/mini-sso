import '@testing-library/jest-dom';

// Fix jsdom cross-realm Uint8Array issue with crypto/jose
Object.defineProperty(Uint8Array, Symbol.hasInstance, {
  value: (instance: unknown) => {
    return (
      instance !== null &&
      typeof instance === 'object' &&
      ((instance as object).constructor?.name === 'Uint8Array' ||
        Object.prototype.toString.call(instance) === '[object Uint8Array]')
    );
  },
  configurable: true,
});
