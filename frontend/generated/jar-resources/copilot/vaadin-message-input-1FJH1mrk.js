import { L as e, H as a, O as r, T as t } from "./copilot-tF9CaZ8e.js";
import { inputFieldProperties as s } from "./vaadin-text-field-AO53X0oA.js";
const p = {
  tagName: "vaadin-message-input",
  displayName: "Message Input",
  elements: [
    {
      selector: "vaadin-message-input vaadin-text-area::part(input-field)",
      displayName: "Text area",
      properties: s
    },
    {
      selector: "vaadin-message-input vaadin-button",
      displayName: "Button",
      properties: [
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
        t.paddingInline
      ]
    }
  ]
};
export {
  p as default
};
