import { R as t, L as e, H as a, O as r, T as o } from "./copilot-tF9CaZ8e.js";
const s = [
  e.backgroundColor,
  e.borderColor,
  e.borderWidth,
  e.borderRadius,
  {
    propertyName: "--lumo-button-size",
    displayName: "Size",
    editorType: a.range,
    presets: r.lumoSize,
    icon: "square"
  },
  o.paddingInline
], d = {
  tagName: "vaadin-button",
  displayName: "Button",
  elements: [
    {
      selector: "vaadin-button",
      displayName: "Root element",
      properties: s
    },
    {
      selector: "vaadin-button::part(label)",
      displayName: "Label",
      properties: t
    }
  ]
};
export {
  d as default,
  s as standardButtonProperties
};
