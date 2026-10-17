// @vitest-environment jsdom
// Drives the real React app through all seven steps. Web Workers are replaced by an in-thread
// shim that runs the same handler the worker runs.
import { describe, expect, it, beforeAll } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { webcrypto } from "node:crypto";
import { handle, type Msg } from "../src/engine/worker";
import App from "../src/App";

beforeAll(() => {
  if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  class ShimWorker extends EventTarget {
    postMessage(m: Msg) {
      setTimeout(() => handle(m, (data) => this.dispatchEvent(Object.assign(new Event("message"), { data }))), 0);
    }
    terminate() {}
  }
  Object.defineProperty(globalThis, "Worker", { value: ShimWorker, configurable: true });
});

const until = (fn: () => void) => waitFor(fn, { timeout: 300_000, interval: 50 });
/** Click like a person: wait until the button exists and is enabled. */
async function click(name: RegExp) {
  let btn!: HTMLButtonElement;
  await until(() => {
    btn = screen.getByRole("button", { name }) as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
  });
  fireEvent.click(btn);
}
async function clickEl(el: HTMLElement) {
  await until(() => expect((el as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(el);
}

describe("ChunavIQ demo app", () => {
  it("walks a voter from setup to verification, with attacks and tampering", async () => {
    render(<App />);
    await click(/start a demo election/i);
    await until(() => expect(screen.getByRole("heading", { name: /manifest fingerprint/i })).toBeTruthy());

    await click(/get my voting credential/i);
    await until(() => expect(screen.getByRole("heading", { name: /what the authority saw/i })).toBeTruthy());

    await clickEl(screen.getByRole("radio", { name: /meera placeholder/i }));
    await click(/seal my ballot/i);
    await until(() => expect(screen.getByRole("button", { name: /check my device/i })).toBeTruthy());

    await click(/check my device/i);
    await until(() => expect(screen.getByText(/gave exactly the same ballot/i)).toBeTruthy());
    await click(/cast my vote/i);
    await until(() => expect(screen.getByLabelText(/your receipt/i)).toBeTruthy());

    await click(/let 110 voters vote/i);
    await until(() => expect(screen.getByText(/111 ballots are in the ballot box/i)).toBeTruthy());

    for (const b of screen.getAllByRole("button", { name: /try it/i })) {
      await clickEl(b);
      await until(() => expect(b.textContent).toBe("Tried"));
    }
    expect(screen.getAllByText(/^Refused \(/).length).toBe(6);
    expect(screen.queryByText(/unexpected outcome/i)).toBeNull();

    await click(/close the polls and count/i);
    await until(() => expect(screen.getByRole("table")).toBeTruthy());
    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
    const total = rows.reduce((n, r) => n + Number(r.querySelector("td.n")!.textContent), 0);
    expect(total).toBe(111);

    await click(/verify the election/i);
    await until(() => expect(screen.getByText(/^Verified\.$/)).toBeTruthy());
    expect(screen.getByText(/your ballot is in the record/i)).toBeTruthy();

    for (const b of screen.getAllByRole("button", { name: /tamper and re-verify/i })) {
      await clickEl(b);
      await until(() => expect(b.textContent).toBe("Done"));
    }
    expect(screen.getAllByText(/^Caught\.$/).length).toBe(3);
    expect(screen.queryByText(/^Not caught\.$/)).toBeNull();
  });
});
