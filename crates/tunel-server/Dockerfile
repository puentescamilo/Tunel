# Imagen del servidor de sincronización de Túnel.
# Se construye desde la raíz del repositorio:
#   docker build -f crates/tunel-server/Dockerfile -t tunel-server .

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p tunel-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /datos --shell /usr/sbin/nologin tunel \
    && mkdir /datos && chown tunel /datos
COPY --from=build /src/target/release/tunel-server /usr/local/bin/tunel-server
USER tunel
ENV TUNEL_DB=/datos/tunel.db \
    TUNEL_ESCUCHA=0.0.0.0:8080
VOLUME /datos
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["tunel-server", "salud"]
CMD ["tunel-server"]
