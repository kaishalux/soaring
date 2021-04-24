const handler = require("./index.js");
describe("use case 1: when pii accessed", () => {
  let event: any;

  beforeEach(() => {
    event = {
      macieFinding: {
        type: "SensitiveData.S3",
      },
      detail: {},
    };
  });

  it("adds informational severity when no cofactors", () => {
    const changedEvent = event;

    // In corporate network
    changedEvent.detail.ipDetails = {
      ip: "129.94.0.1",
    };
    // Not public bucket
    changedEvent.macieFinding.resourcesAffected = {
      s3Bucket: { publicAccess: { effectivePermission: "NOT_PUBLIC" } },
    };

    return handler.handler(changedEvent).then((result: any) => {
      expect(result.severity.matches).toHaveLength(1);

      const match = result.severity.matches[0];
      expect(match.severity.description).toBe("INFORMATIONAL");
      expect(match.cofactors).toStrictEqual([]);
    });
  });

  it("adds high severity when outside corporate network", () => {
    const changedEvent = event;

    // Outside corporate network
    changedEvent.detail.ipDetails = {
      ip: "111.0.0.0",
    };
    // Not public bucket
    changedEvent.macieFinding.resourcesAffected = {
      s3Bucket: { publicAccess: { effectivePermission: "NOT_PUBLIC" } },
    };

    return handler.handler(changedEvent).then((result: any) => {
      expect(result.severity.matches).toHaveLength(1);

      const match = result.severity.matches[0];
      expect(match.severity.description).toBe("HIGH");
    });
  });

  it("adds critical severity when public bucket", () => {
    const changedEvent = event;

    // Outside corporate network
    changedEvent.detail.ipDetails = {
      ip: "129.94.0.1",
    };
    // Not public bucket
    changedEvent.macieFinding.resourcesAffected = {
      s3Bucket: { publicAccess: { effectivePermission: "PUBLIC" } },
    };

    return handler.handler(changedEvent).then((result: any) => {
      expect(result.severity.matches).toHaveLength(1);

      const match = result.severity.matches[0];
      expect(match.severity.description).toBe("CRITICAL");
    });
  });
});
