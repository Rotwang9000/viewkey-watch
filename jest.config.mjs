// ESM-flavoured Jest config. Pure-Node ESM still needs the experimental flag,
// hence the `--experimental-vm-modules` in package.json's `test` script.
export default {
	testEnvironment: 'node',
	testMatch: ['**/test/**/*.test.js'],
	moduleFileExtensions: ['js', 'mjs', 'json'],
	transform: {},
	clearMocks: true,
	verbose: true,
	collectCoverageFrom: ['src/**/*.js'],
	coveragePathIgnorePatterns: ['/node_modules/']
};
