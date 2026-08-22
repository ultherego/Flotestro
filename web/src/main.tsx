import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { ApiError } from "./lib/api";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Dane odswiezaja sie same, ale rzadziej: odswiezanie co dziesiec sekund
      // kazdego zapytania na kazdym ekranie zamienialo panel w migotanie,
      // bo widok wracal do stanu wczytywania albo do bledu i z powrotem.
      refetchInterval: 30_000,
      staleTime: 15_000,
      // Poprzednie dane zostaja na ekranie w czasie odswiezania. Bez tego
      // kazde odswiezenie kasowalo widok na czas trwania zapytania.
      placeholderData: (poprzednie: unknown) => poprzednie,
      // Odmowa i brak uwierzytelnienia sa odpowiedzia serwera, a nie awaria
      // sieci: ponawianie ich niczego nie naprawia, a mnozy migotanie.
      retry: (count, error) => {
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
        return count < 2;
      },
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
