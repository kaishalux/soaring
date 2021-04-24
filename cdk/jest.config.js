module.exports = {
  roots: ["<rootDir>/lib/lambda"],
  testMatch: ["**/*.test.ts"],
  transform: {
    "^.+\\.tsx?$": "ts-jest",
  },
};
