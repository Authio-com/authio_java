package com.authio;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/** A tiny hand-rolled HTTP mock server for SDK transport tests. */
final class MockServer implements AutoCloseable {
  private final HttpServer server;
  final List<Recorded> requests = new CopyOnWriteArrayList<>();

  MockServer(Function<Recorded, Response> handler) throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        (HttpExchange ex) -> {
          String body = readBody(ex.getRequestBody());
          Recorded rec =
              new Recorded(
                  ex.getRequestMethod(),
                  ex.getRequestURI().getPath(),
                  ex.getRequestURI().getRawQuery(),
                  flatten(ex.getRequestHeaders()),
                  body);
          requests.add(rec);
          Response resp;
          try {
            resp = handler.apply(rec);
          } catch (Exception e) {
            resp = new Response(500, "{\"code\":\"handler_error\"}");
          }
          byte[] out = resp.body == null ? new byte[0] : resp.body.getBytes(StandardCharsets.UTF_8);
          ex.getResponseHeaders().add("Content-Type", "application/json");
          if (resp.status == 204 || out.length == 0) {
            ex.sendResponseHeaders(resp.status, -1);
          } else {
            ex.sendResponseHeaders(resp.status, out.length);
            ex.getResponseBody().write(out);
          }
          ex.close();
        });
    server.start();
  }

  String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  @Override
  public void close() {
    server.stop(0);
  }

  private static String readBody(InputStream in) throws IOException {
    return new String(in.readAllBytes(), StandardCharsets.UTF_8);
  }

  private static Map<String, String> flatten(Map<String, List<String>> headers) {
    Map<String, String> out = new java.util.HashMap<>();
    for (Map.Entry<String, List<String>> e : headers.entrySet()) {
      if (!e.getValue().isEmpty()) {
        out.put(e.getKey().toLowerCase(), e.getValue().get(0));
      }
    }
    return out;
  }

  static final class Recorded {
    final String method;
    final String path;
    final String query;
    final Map<String, String> headers;
    final String body;

    Recorded(String method, String path, String query, Map<String, String> headers, String body) {
      this.method = method;
      this.path = path;
      this.query = query;
      this.headers = headers;
      this.body = body;
    }

    String header(String name) {
      return headers.get(name.toLowerCase());
    }
  }

  static final class Response {
    final int status;
    final String body;

    Response(int status, String body) {
      this.status = status;
      this.body = body;
    }
  }

  /** Convenience builder: respond from a fixed list, one per call, then repeat last. */
  static Function<Recorded, Response> sequence(Response... responses) {
    List<Response> list = new ArrayList<>(List.of(responses));
    int[] i = {0};
    return req -> {
      Response r = list.get(Math.min(i[0], list.size() - 1));
      i[0]++;
      return r;
    };
  }
}
