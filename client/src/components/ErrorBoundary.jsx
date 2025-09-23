import React from "react";

export default function ErrorBoundary({ error }) {
  return (
    <div style={{ color: "red", padding: 20 }}>
      <h2>Something went wrong!</h2>
      <pre style={{ whiteSpace: "pre-wrap" }}>
        {typeof error === "string"
          ? error
          : error?.message || JSON.stringify(error, null, 2)}
      </pre>
    </div>
  );
}
