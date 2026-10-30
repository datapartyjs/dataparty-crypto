//! a few of our crypto deps ship ESM only, babel them down so jest can require them
const esmPackages = [
  '@stablelib',
  '@noble'
]

module.exports = {
  roots: ['<rootDir>'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
    '^.+\\.jsx?$': [
      'babel-jest',
      { presets: [['@babel/preset-env', { targets: { node: 'current' } }]] }
    ]
  },
  testRegex: '(/test/*|(\\.|/)(test|spec))\\.ts?$',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  setupFiles: ['<rootDir>/test/setup.ts'],
  transformIgnorePatterns: [`/node_modules/(?!(${esmPackages.join('|')})/)`],
  //! we ship through babel, which strips types without checking them
  globals: { 'ts-jest': { diagnostics: false } }
}
