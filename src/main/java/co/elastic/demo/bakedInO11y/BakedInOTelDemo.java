package co.elastic.demo.bakedInO11y;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.core.GetResponse;
import co.elastic.clients.elasticsearch.core.SearchResponse;
import co.elastic.clients.elasticsearch.core.search.Hit;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import co.elastic.clients.transport.rest_client.RestClientTransport;
import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Scope;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import io.opentelemetry.semconv.ResourceAttributes;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.elasticsearch.client.RestClient;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

public class BakedInOTelDemo {

    private static final String[] NAMES = {"Alex", "Emily", "Gil"};
    private static final String ES_ENDPOINT_KEY = "elasticsearch_url";
    private static final String ES_PASSWORD_KEY = "elasticsearch_pw";
    private static final String ES_USER_KEY = "elasticsearch_user";
    private static final String OTLP_ENDPOINT_KEY = "otlp_endpoint";
    private static final String OTLP_SECRET_TOKEN_KEY = "otlp-secret-token";

    public static void main(String[] args) throws IOException {
        BakedInOTelDemo demo = new BakedInOTelDemo();
        demo.run();
        demo.close();
    }

    private final ResourceBundle resourceBundle;
    private RestClient restClient;
    private final ElasticsearchClient esClient;
    private OpenTelemetrySdk openTelemetry;
    private Tracer otelTracer;
    private final Random rand = new Random(System.currentTimeMillis());

    private BakedInOTelDemo() {
        resourceBundle = ResourceBundle.getBundle("config");
        initOtel();
        esClient = initElasticClient();
    }

    private void initOtel() {
        Resource resource = Resource.getDefault().toBuilder().put(ResourceAttributes.SERVICE_NAME, "baking-demo").put(ResourceAttributes.SERVICE_VERSION, "0.1.0").build();

        String endpoint = resourceBundle.getString(OTLP_ENDPOINT_KEY);
        String auth_header = "Bearer " + resourceBundle.getString(OTLP_SECRET_TOKEN_KEY);

        SdkTracerProvider sdkTracerProvider = SdkTracerProvider.builder()
                .addSpanProcessor(SimpleSpanProcessor.create(OtlpGrpcSpanExporter.builder().setEndpoint(endpoint).addHeader("Authorization", auth_header).build()))
                .setResource(resource)
                .build();


        openTelemetry = OpenTelemetrySdk.builder()
                .setTracerProvider(sdkTracerProvider)
                .setPropagators(ContextPropagators.create(TextMapPropagator.composite(W3CTraceContextPropagator.getInstance(), W3CBaggagePropagator.getInstance())))
                .buildAndRegisterGlobal();

        otelTracer = openTelemetry.getTracer("MyTracer");
    }

    private ElasticsearchClient initElasticClient() {
        String esEndpoint = resourceBundle.getString(ES_ENDPOINT_KEY);
        String esScheme = esEndpoint.substring(0, esEndpoint.indexOf(":"));
        if (esEndpoint.startsWith("https://")) {
            esEndpoint = esEndpoint.substring(8);
        }
        int esPort = esScheme.equals("https") ? 443 : 80;
        String esUser = resourceBundle.getString(ES_USER_KEY);
        String esPassword = resourceBundle.getString(ES_PASSWORD_KEY);

        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(esUser, esPassword));

        restClient = RestClient.builder(new HttpHost(esEndpoint, esPort, esScheme))
                .setHttpClientConfigCallback(httpClientBuilder -> httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider))
                .build();

        return new ElasticsearchClient(new RestClientTransport(restClient, new JacksonJsonpMapper()));
    }

    private void close() throws IOException {
        restClient.close();
        esClient.shutdown();
        openTelemetry.close();
    }

    private void run() throws IOException {
        Span rootSpan = otelTracer.spanBuilder("Demo run()").startSpan();
        try (Scope ss = rootSpan.makeCurrent()) {
            // ------------------------------------------------
            // Doing some Elasticsearch requests
            // ------------------------------------------------
            indexDocument();
            List<String> ids = searchDocuments();
            if (!ids.isEmpty()) {
                Doc doc = getDocument(ids.get(0));
                System.out.println("First Document:" + doc);
            }
            // ------------------------------------------------
        } finally {
            rootSpan.end();
        }
    }

    private void indexDocument() throws IOException {
        Doc doc = new Doc("My Document", new Date(), NAMES[rand.nextInt(NAMES.length)]);
        System.out.println("Indexing document:" + doc);
        esClient.index(i -> i.index("custom-docs").document(doc));
    }

    private List<String> searchDocuments() throws IOException {
        SearchResponse<Doc> searchResponse = esClient.search(s -> s.query(q -> q.term(t -> t.field("user.keyword").value("Alex"))).index("custom-docs"), Doc.class);
        List<String> ids = searchResponse.hits().hits().stream().map(Hit::id).collect(Collectors.toList());
        System.out.println("IDs from search result:" + ids);
        return ids;
    }

    private Doc getDocument(String id) throws IOException {
        GetResponse<Doc> response = esClient.get(g -> g.index("custom-docs").id(id), Doc.class);
        return response.source();
    }
}