import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { ApiError } from "./lib/api";
import { I18nProvider } from "./i18n";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The data refreshes on its own, but less often: refreshing every
      // query on every screen every ten seconds turned the panel into a
      // flicker, because the view went back to loading or to an error and
      // back again.
      refetchInterval: 30_000,
      staleTime: 15_000,
      // The previous data stays on the screen while refreshing. Without it
      // every refresh wiped the view for the duration of the query.
      placeholderData: (previous: unknown) => previous,
      // A refusal and missing authentication are a server answer, not a
      // network failure: retrying them fixes nothing and multiplies the
      // flicker.
      retry: (count, error) => {
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
        return count < 2;
      },
    },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </QueryClientProvider>
    </I18nProvider>
  </React.StrictMode>,
);
