import { expect, test } from "bun:test";
import { VERITIO_CORE_VERSION } from "../index";

test("exports the exact public core package identity without reading host environment", () => {
  expect(VERITIO_CORE_VERSION).toBe("0.4.8");
});
