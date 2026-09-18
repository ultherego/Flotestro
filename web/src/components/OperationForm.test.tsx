import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { OperationForm } from "./OperationForm";
import { emptyForm, operationForm, type FormValue, type OperationEntry } from "../lib/operations";

/* The renderer is checked against one entry of the real registry rather
   than an invented one: what matters is that an operation described as
   data ends up as a form the operator can use, and that the advanced view
   hands the payload back to the fields as soon as they can carry it. */

function entryOf(action: string): OperationEntry {
  const entry = operationForm(action);
  if (!entry) throw new Error(`the registry has no form for ${action}`);
  return entry;
}

function draw(entry: OperationEntry, value: FormValue, json = "") {
  const onChange = vi.fn();
  const onJson = vi.fn();
  render(<OperationForm entry={entry} value={value} onChange={onChange} json={json} onJson={onJson} />);
  return { onChange, onJson };
}

afterEach(cleanup);

describe("OperationForm", () => {
  const toggle = entryOf("unit.enable.set");

  it("draws a control for every field the entry describes", () => {
    draw(toggle, emptyForm(toggle));
    expect(screen.getByLabelText(/^Unit/)).toBeInstanceOf(HTMLInputElement);
    expect(screen.getByLabelText(/^Start it at boot/)).toBeInstanceOf(HTMLInputElement);
    expect(screen.getByText("Decide whether a service starts at boot")).toBeInTheDocument();
  });

  it("hands back the whole form when one field changes", () => {
    const { onChange } = draw(toggle, emptyForm(toggle));
    fireEvent.change(screen.getByLabelText(/^Unit/), { target: { value: "cron.service" } });
    expect(onChange).toHaveBeenCalledWith({ unit: "cron.service", enabled: false });

    fireEvent.click(screen.getByLabelText(/^Start it at boot/));
    expect(onChange).toHaveBeenLastCalledWith({ unit: "", enabled: true });
  });

  it("says what is missing where it is missing", () => {
    draw(toggle, emptyForm(toggle));
    // The field carries the sentence, and the block under the form repeats
    // it - one reason, said once, in both places an operator looks.
    expect(screen.getAllByText("Name the unit this acts on.").length).toBeGreaterThan(0);
  });

  it("draws the fields of an operation that takes none", () => {
    const repair = entryOf("packages.repair");
    draw(repair, emptyForm(repair));
    expect(screen.getByText("This operation takes no settings.")).toBeInTheDocument();
  });

  it("says where a plan comes before the change", () => {
    const ensure = entryOf("file.ensure");
    draw(ensure, emptyForm(ensure));
    expect(screen.getByText(/planning step/)).toBeInTheDocument();
  });
});

describe("the advanced view", () => {
  const toggle = entryOf("unit.enable.set");
  const filled: FormValue = { unit: "cron.service", enabled: true };

  it("shows exactly the payload the fields produce", () => {
    draw(toggle, filled);
    fireEvent.click(screen.getByLabelText("Advanced (JSON)"));
    const box = screen.getByLabelText(/^Payload/) as HTMLTextAreaElement;
    expect(JSON.parse(box.value)).toEqual({ unit_toggle: { unit: "cron.service", enabled: true } });
    expect(screen.queryByLabelText(/^Unit/)).toBeNull();
  });

  it("gives the payload back to the fields as soon as they can carry it", () => {
    const { onChange, onJson } = draw(toggle, filled);
    fireEvent.click(screen.getByLabelText("Advanced (JSON)"));
    fireEvent.change(screen.getByLabelText(/^Payload/), {
      target: { value: '{"unit_toggle":{"unit":"nginx.service","enabled":false}}' },
    });
    expect(onChange).toHaveBeenCalledWith({ unit: "nginx.service", enabled: false });
    // The order stops being the hand-written text: the fields are what it
    // is made of again.
    expect(onJson).toHaveBeenLastCalledWith("");
  });

  it("keeps a payload the fields cannot show exactly as typed", () => {
    const { onChange, onJson } = draw(toggle, filled);
    fireEvent.click(screen.getByLabelText("Advanced (JSON)"));
    const typed = '{"unit_toggle":{"unit":"nginx.service","force":true}}';
    fireEvent.change(screen.getByLabelText(/^Payload/), { target: { value: typed } });
    expect(onJson).toHaveBeenLastCalledWith(typed);
    expect(onChange).not.toHaveBeenCalled();
    expect(screen.getByText(/travels exactly as typed/)).toBeInTheDocument();
  });

  it("says when the text is not JSON at all", () => {
    const { onJson } = draw(toggle, filled);
    fireEvent.click(screen.getByLabelText("Advanced (JSON)"));
    fireEvent.change(screen.getByLabelText(/^Payload/), { target: { value: "{not json" } });
    expect(onJson).toHaveBeenLastCalledWith("{not json");
    expect(screen.getByText("This is not valid JSON.")).toBeInTheDocument();
  });

  it("opens on a payload the order already carries by hand", () => {
    const typed = '{"unit_toggle":{"unit":"nginx.service","force":true}}';
    draw(toggle, filled, typed);
    const box = screen.getByLabelText(/^Payload/) as HTMLTextAreaElement;
    expect(box.value).toBe(typed);
  });

  it("gives the order back to the fields when it is closed", () => {
    const typed = '{"unit_toggle":{"unit":"nginx.service","force":true}}';
    const { onJson } = draw(toggle, filled, typed);
    fireEvent.click(screen.getByLabelText("Advanced (JSON)"));
    expect(onJson).toHaveBeenLastCalledWith("");
    expect(screen.getByLabelText(/^Unit/)).toBeInstanceOf(HTMLInputElement);
  });
});
