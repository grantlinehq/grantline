import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { Product } from "./product/Workspace";
import type { Status } from "./product/api";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "./styles.css";
import "./product/product.css";
function Root() {
  const [status, setStatus] = useState<Status | null | undefined>(undefined);
  const [error, setError] = useState("");
  useEffect(() => {
    fetch("/api/v1/status", { credentials: "same-origin" })
      .then(async (r) => {
        if (r.status === 404) {
          setStatus(null);
          return;
        }
        if (!r.ok)
          throw new Error(
            "The workspace is unavailable. Check the service and database, then retry.",
          );
        const value = await r.json();
        if (value.mode !== "server")
          throw new Error("Unexpected server response.");
        setStatus(value);
      })
      .catch((e) => setError(e.message));
  }, []);
  if (error)
    return (
      <div className="product-loading" role="alert">
        <p>{error}</p>
        <button className="button" onClick={() => location.reload()}>
          Retry
        </button>
      </div>
    );
  if (status === undefined)
    return (
      <div className="product-loading" role="status">
        Opening Grantline…
      </div>
    );
  return status ? <Product initial={status} /> : <App />;
}
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
