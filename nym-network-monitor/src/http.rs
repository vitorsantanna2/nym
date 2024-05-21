use crate::accounting::{NetworkAccount, NetworkAccountStats, NodeStats};
use crate::handlers::{
    accounting_handler, graph_handler, mermaid_handler, mix_dot_handler, node_stats_handler,
    recv_handler, send_handler, sent_handler, stats_handler, FragmentsReceived, FragmentsSent,
};
use axum::routing::{get, post};
use axum::Router;
use nym_sphinx::chunking::fragment::FragmentHeader;
use nym_sphinx::chunking::{ReceivedFragment, SentFragment};
use std::future::IntoFuture;
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::ClientsWrapper;

pub struct HttpServer {
    listener: SocketAddr,
    cancel: CancellationToken,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::accounting_handler,
        crate::handlers::graph_handler,
        crate::handlers::mermaid_handler,
        crate::handlers::mix_dot_handler,
        crate::handlers::node_stats_handler,
        crate::handlers::recv_handler,
        crate::handlers::send_handler,
        crate::handlers::sent_handler,
        crate::handlers::stats_handler,
    ),
    components(schemas(
        FragmentHeader,
        FragmentsReceived,
        FragmentsSent,
        NetworkAccount,
        NetworkAccountStats,
        NodeStats,
        ReceivedFragment,
        SentFragment,
    ))
)]
struct ApiDoc;

#[derive(Clone)]
pub struct AppState {
    clients: ClientsWrapper,
}

impl AppState {
    pub fn clients(&self) -> &ClientsWrapper {
        &self.clients
    }
}

impl HttpServer {
    pub fn new(listener: SocketAddr, cancel: CancellationToken) -> Self {
        HttpServer { listener, cancel }
    }

    pub async fn run(self, clients: ClientsWrapper) -> anyhow::Result<()> {
        let n_clients = clients.read().await.len();
        let state = AppState { clients };
        let app = Router::new()
            .route("/v1/send", post(send_handler).with_state(state))
            .merge(SwaggerUi::new("/v1/ui").url("/v1/docs/openapi.json", ApiDoc::openapi()))
            .route("/v1/accounting", get(accounting_handler))
            .route("/v1/sent", get(sent_handler))
            .route("/v1/dot/:mix_id", get(mix_dot_handler))
            .route("/v1/dot", get(graph_handler))
            .route("/v1/mermaid", get(mermaid_handler))
            .route("/v1/stats", get(stats_handler))
            .route("/v1/node/:mix_id", get(node_stats_handler))
            .route("/v1/received", get(recv_handler));
        let listener = tokio::net::TcpListener::bind(self.listener).await?;

        let shutdown_future = self.cancel.cancelled();
        let server_future = axum::serve(listener, app).into_future();

        println!("##########################################################################################");
        println!("######################### HTTP server running, with {} clients ############################################", n_clients);
        println!("##########################################################################################");

        tokio::select! {
            _ = shutdown_future => {
                println!("received shutdown");
            }
            res = server_future => {
                println!("the http server has terminated");
                if let Err(err) = res {
                    println!("with the following error: {err}");
                    return Err(err.into())
                }
            }
        }

        Ok(())
    }
}
