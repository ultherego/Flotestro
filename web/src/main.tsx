import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Panel pokazuje stan floty, wiec dane odswiezaja sie same, ale nie
      // czesciej niz co kilka sekund: kazde odswiezenie to zapytanie do bazy.
      refetchInterval: 10_000,
      staleTime: 5_000,
      retry: (count, error) =>
        !(error instanceof Error && error.message.includes("401")) && count < 2,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
