import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { mockMode } from "./api/client";
import { stashControls } from "./api/mock/controls";
import { App } from "./App";
import { reloadWhenRestored } from "./lib/page-lifecycle";
import "./index.css";

if (mockMode) stashControls();
reloadWhenRestored();

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
