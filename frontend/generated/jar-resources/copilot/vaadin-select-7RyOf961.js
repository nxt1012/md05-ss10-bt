import { L as e, T as o, K as r, N as t } from "./copilot-tF9CaZ8e.js";
import { labelProperties as i, helperTextProperties as l, errorMessageProperties as s } from "./vaadin-text-field-AO53X0oA.js";
const c = {
  tagName: "vaadin-select",
  displayName: "Select",
  elements: [
    {
      selector: "vaadin-select::part(input-field)",
      displayName: "Field",
      properties: [
        e.backgroundColor,
        e.borderColor,
        e.borderWidth,
        e.borderRadius,
        o.height,
        o.paddingInline
      ]
    },
    {
      selector: "vaadin-select vaadin-select-value-button>vaadin-select-item",
      displayName: "Field text",
      properties: [r.textColor, r.fontSize, r.fontWeight]
    },
    {
      selector: "vaadin-select::part(toggle-button)",
      displayName: "Field toggle button",
      properties: [t.iconColor, t.iconSize]
    },
    {
      selector: "vaadin-select::part(label)",
      displayName: "Label",
      properties: i
    },
    {
      selector: "vaadin-select::part(helper-text)",
      displayName: "Helper text",
      properties: l
    },
    {
      selector: "vaadin-select::part(error-message)",
      displayName: "Error message",
      properties: s
    },
    {
      selector: "vaadin-select-overlay::part(overlay)",
      displayName: "Overlay",
      properties: [
        e.backgroundColor,
        e.borderColor,
        e.borderWidth,
        e.borderRadius,
        e.padding
      ]
    },
    {
      selector: "vaadin-select-overlay vaadin-select-item",
      displayName: "Overlay items",
      properties: [r.textColor, r.fontSize, r.fontWeight]
    },
    {
      selector: "vaadin-select-overlay vaadin-select-item::part(checkmark)::before",
      displayName: "Overlay item checkmark",
      properties: [t.iconColor, t.iconSize]
    }
  ],
  async setupElement(a) {
    a.overlayClass = a.getAttribute("class");
  }
};
export {
  c as default
};
