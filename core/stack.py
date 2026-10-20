from __future__ import annotations
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

SIGNALS = ("web", "templates", "iac", "llm", "messaging", "multiservice", "ldap", "multitenant")

SIGNAL_LABELS = {
    "web": "web server or front-end code",
    "templates": "server-side templates",
    "iac": "Docker, IaC or CI files",
    "llm": "LLM or MCP libraries",
    "messaging": "message queues or event buses",
    "multiservice": "more than one service, or gRPC",
    "ldap": "LDAP code",
    "multitenant": "tenant or organisation identifiers",
}

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "env",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", ".nuxt", "bower_components",
    "Pods", ".gradle", ".idea", ".vscode", "coverage", ".terraform", "site-packages",
})
_MAX_FILES = 60000
_MAX_FILE_BYTES = 512 * 1024
_MAX_SCAN_BYTES = 96 * 1024 * 1024

_MANIFESTS = frozenset({
    "package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "pipfile",
    "setup.py", "setup.cfg", "go.mod", "gemfile", "composer.json", "pom.xml", "build.gradle",
    "build.gradle.kts", "cargo.toml", "mix.exs", "package.swift", "packages.config",
    "directory.packages.props", "deno.json", "bun.lockb", "environment.yml",
})
_SOURCE_EXT = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".kts", ".scala",
    ".groovy", ".rb", ".php", ".cs", ".vb", ".fs", ".rs", ".ex", ".exs", ".erl", ".swift", ".m",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".vue", ".svelte", ".dart", ".lua", ".pl", ".pm", ".clj",
    ".yaml", ".yml", ".xml", ".properties", ".toml", ".conf", ".ini", ".json", ".sql", ".graphql",
})
_TEMPLATE_EXT = frozenset({
    ".j2", ".jinja", ".jinja2", ".twig", ".tpl", ".mustache", ".hbs", ".handlebars", ".ejs",
    ".pug", ".jade", ".njk", ".liquid", ".erb", ".haml", ".slim", ".cshtml", ".razor", ".vm",
    ".ftl", ".ftlh", ".gohtml", ".tmpl", ".mako", ".jsp", ".jspx", ".cfm", ".eex", ".heex",
    ".leex", ".php", ".phtml", ".asp", ".aspx", ".ascx", ".blade",
})
_WEB_EXT = frozenset({
    ".html", ".htm", ".xhtml", ".jsx", ".tsx", ".vue", ".svelte", ".php", ".jsp", ".asp",
    ".aspx", ".cshtml", ".razor", ".erb", ".ejs", ".hbs", ".twig", ".graphql", ".gql",
})
_IAC_NAMES = frozenset({
    "dockerfile", "containerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml",
    "compose.yaml", "jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml",
    "bitbucket-pipelines.yml", ".travis.yml", "cloudbuild.yaml", "cloudbuild.yml",
    "serverless.yml", "serverless.yaml", "pulumi.yaml", "cdk.json", "chart.yaml",
    "kustomization.yaml", "kustomization.yml", "skaffold.yaml", "vagrantfile", "fly.toml",
    "render.yaml", "app.yaml", "procfile", "ansible.cfg", "template.yaml", "template.yml",
    "samconfig.toml", "netlify.toml", "vercel.json", "wrangler.toml", "nomad.hcl",
    "terragrunt.hcl", "buildspec.yml", "appspec.yml", "codemagic.yaml", ".drone.yml",
})
_IAC_EXT = frozenset({".tf", ".tfvars", ".hcl", ".bicep", ".nomad"})
_IAC_DIRS = (".github/workflows/", ".circleci/", ".buildkite/", ".gitea/workflows/",
             ".forgejo/workflows/", "k8s/", "kubernetes/", "helm/", "charts/", "terraform/",
             "deploy/", "deployment/", "manifests/", "ansible/", "playbooks/", "infra/")


def _words(*items: str) -> re.Pattern:
    return re.compile(r"(?<![\w.-])(?:" + "|".join(items) + r")(?![\w-])", re.IGNORECASE)


_DEP_SIGNALS = {
    "web": _words(
        "express", "koa", "fastify", "@hapi/hapi", "hapi", r"@nestjs/[\w-]+", "next", "nuxt",
        "react", "react-dom", "vue", "@angular/core", "svelte", "@sveltejs/kit", "remix",
        r"@remix-run/[\w-]+", "astro", "solid-js", "preact", "django", "flask", "fastapi",
        "starlette", "tornado", "aiohttp", "pyramid", "bottle", "sanic", "falcon", "quart",
        "litestar", "werkzeug", "spring-boot-starter-web", "spring-boot-starter-webflux",
        "spring-web", "spring-webmvc", "spring-webflux", "jakarta.servlet-api", "javax.servlet-api",
        r"quarkus-[\w-]+", r"micronaut-[\w-]+", "struts2-core", "javalin", r"ktor-server-[\w-]+",
        "dropwizard-core", r"play_[\d.]+", "github.com/gin-gonic/gin", "github.com/labstack/echo",
        r"github.com/gofiber/fiber(?:/v\d)?", r"github.com/go-chi/chi(?:/v\d)?",
        "github.com/gorilla/mux", "rails", "sinatra", "rack", "hanami", "roda",
        "laravel/framework", r"symfony/[\w-]+", "slim/slim", "cakephp/cakephp", "yiisoft/yii2",
        "codeigniter4/framework", r"microsoft\.aspnetcore[\w.]*", "actix-web", "axum", "rocket",
        "warp", "hyper", "poem", "tide", "phoenix", "plug_cowboy", "vapor", "graphql",
        r"apollo-server[\w-]*", r"@apollo/server", "socket.io", "ws", "grpc-gateway",
    ),
    "templates": _words(
        "jinja2", "mako", "chameleon", "genshi", "django", "twig/twig", "smarty/smarty",
        "laravel/framework", "thymeleaf", r"spring-boot-starter-thymeleaf", "freemarker",
        r"spring-boot-starter-freemarker", "velocity", "velocity-engine-core", "pebble",
        "handlebars", "express-handlebars", "hbs", "ejs", "pug", "jade", "nunjucks", "mustache",
        "hogan.js", "liquidjs", "liquid", "eta", "marko", "haml", "slim", "erubi", "erubis",
        "rails", "scriban", "dotliquid", "tera", "askama", "handlebars-rust", "pongo2",
        "github.com/flosch/pongo2", "github.com/cloudykit/jet", "jte", "jinjava", "chevron",
        "airspeed", "jinja2-time", "phoenix_html",
    ),
    "llm": _words(
        "openai", "anthropic", r"@anthropic-ai/[\w-]+", r"langchain[\w-]*", r"@langchain/[\w-]+",
        "langgraph", r"llama[-_]index[\w-]*", "llamaindex", "transformers", "huggingface_hub",
        "mcp", r"@modelcontextprotocol/[\w-]+", "fastmcp", "ollama", "google-generativeai",
        "google-genai", r"@google/generative-ai", r"@google/genai", "cohere", "cohere-ai",
        "mistralai", r"@mistralai/[\w-]+", "litellm", "semantic-kernel", r"microsoft\.semantickernel[\w.]*",
        "autogen", r"autogen-[\w-]+", "pyautogen", "crewai", "haystack-ai", "farm-haystack",
        "instructor", "dspy", "dspy-ai", "guidance", "vllm", r"@ai-sdk/[\w-]+", "groq",
        "together", "replicate", "pydantic-ai", "smolagents", "openai-agents", "chromadb",
        "pinecone", "pinecone-client", "weaviate-client", "qdrant-client", r"spring-ai-[\w-]+",
        "github.com/sashabaranov/go-openai", "github.com/openai/openai-go", "langchain4j",
        r"dev.langchain4j", "async-openai", "llm",
    ),
    "messaging": _words(
        "kafka", "kafkajs", "kafka-python", "confluent-kafka", "aiokafka", "github.com/ibm/sarama",
        "github.com/shopify/sarama", "github.com/segmentio/kafka-go", "amqp", "amqplib",
        "amqp-connection-manager", "pika", "aio-pika", "aiormq", "celery", "kombu", "rq",
        "dramatiq", "huey", "sidekiq", "resque", "good_job", "bull", "bullmq", "bee-queue",
        "agenda", "nats", "nats-py", "nats.go", "github.com/nats-io/nats.go", r"@aws-sdk/client-sqs",
        r"@aws-sdk/client-sns", r"@aws-sdk/client-eventbridge", r"@aws-sdk/client-kinesis",
        "google-cloud-pubsub", r"@google-cloud/pubsub", "azure-servicebus", r"@azure/service-bus",
        "azure-eventhub", "pyzmq", "zeromq", "zmq", "paho-mqtt", "mqtt", "nsq", "pulsar-client",
        "activemq", "spring-kafka", "spring-amqp", "spring-rabbit", r"spring-cloud-stream[\w-]*",
        "masstransit", "nservicebus", "rabbitmq.client", "confluent.kafka", "broadway", "oban",
        "faust", "faust-streaming", "temporalio", r"@temporalio/[\w-]+", "redis-streams",
    ),
    "multiservice": _words(
        "grpc", "grpcio", r"@grpc/grpc-js", "google.golang.org/grpc", r"grpc-[\w-]+", "tonic",
        "protobuf", "protobufjs", "google-protobuf", "thrift", "dapr", "nameko", "moleculer",
    ),
    "ldap": _words(
        "ldap", "ldap3", "python-ldap", "django-auth-ldap", "ldapjs", "ldapts", "activedirectory",
        "activedirectory2", "passport-ldapauth", "spring-ldap-core", "spring-security-ldap",
        "unboundid-ldapsdk", "github.com/go-ldap/ldap", r"github.com/go-ldap/ldap/v\d", "net-ldap",
        "adldap2/adldap2", "directorytree/ldaprecord", "symfony/ldap", "novell.directory.ldap",
        r"system\.directoryservices[\w.]*", "ldap3-rs", "exldap",
    ),
}

_CONTENT_SIGNALS = {
    "web": re.compile(
        r'"net/http"|@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b|@RestController\b|'
        r"@Controller\b|@Path\(|\bHttpServlet\b|\bhttp\.HandleFunc\b|"
        r"\b(?:app|router|server)\.(?:get|post|put|delete|patch|route|use)\(|"
        r"@app\.(?:route|get|post|put|delete)\b|\burlpatterns\b|\bMapGet\(|\bMapPost\(|"
        r"\bcreateServer\(|\bServeMux\b|\bWSGIApplication\b|\basgi\b|<html\b|"
        r"\bdocument\.getElementById\b|\binnerHTML\b|\bResponse\(|\bHttpResponse\b"),
    "templates": re.compile(
        r'"html/template"|"text/template"|\brender_template(?:_string)?\(|\brender_to_string\(|'
        r"\bTemplateResponse\b|\bjinja2\b|\bEnvironment\(\s*loader|\bres\.render\(|"
        r"\bERB\.new\b|\bHandlebars\.compile\b|\bMustache\.render\b|\bVelocityEngine\b|"
        r"\bfreemarker\.template\b|\bTemplateEngine\b|\bnew Template\(|\bTemplate\(\s*['\"]|"
        r"\bnunjucks\.render|\bejs\.render|\bpug\.render|\bView::make\b|\bview\(\s*['\"]|"
        r"\b\$this->render\(|\bRazorEngine\b|\bThymeleaf\b|\bTwig\\\\Environment\b"),
    "llm": re.compile(
        r"\bfrom\s+(?:openai|anthropic|langchain\w*|llama_index|transformers|mcp|litellm)\b|"
        r"\bimport\s+(?:openai|anthropic|litellm)\b|require\(\s*['\"](?:openai|@anthropic-ai/sdk)['\"]\s*\)|"
        r"['\"]@modelcontextprotocol/|\bchat\.completions\.create\b|\bmessages\.create\(|"
        r"\bChatOpenAI\b|\bChatAnthropic\b|\bgenerateContent\(|\bOllama\(|\bMcpServer\b|"
        r"\bFastMCP\b|\bopenai\.com/v1\b|\bapi\.anthropic\.com\b|\bgenerativelanguage\.googleapis\b"),
    "messaging": re.compile(
        r"(?i)\b(?:kafka|rabbitmq|amqps?://|sqs|sns|pubsub|eventbridge|kinesis|nats://|"
        r"celery|servicebus|event ?hub|mqtt|zeromq|publish_message|send_message_batch)\b"),
    "multiservice": re.compile(r"\bgrpc\b|\bprotobuf\b|\.proto\b|\bservice_name\b|\bservices:\s*$",
                               re.IGNORECASE | re.MULTILINE),
    "ldap": re.compile(
        r"(?i)\bldaps?://|\bInitialDirContext\b|\bDirContext\b|\bldap_(?:search|bind|connect)\b|"
        r"\bldap3\b|\bldapjs\b|\bDirectorySearcher\b|\bLdapTemplate\b|\bsearch_s\(|\bsimple_bind_s\b"),
    "multitenant": re.compile(
        r"(?i)\btenant|\b(?:org|organi[sz]ation|workspace|account)_?id\b|\b(?:orgId|workspaceId|accountId)\b|"
        r"\bmulti[-_ ]?tenan"),
    "iac": re.compile(r"(?m)^\s*apiVersion:\s*\S+[\s\S]{0,400}?^\s*kind:\s*\w+"),
}


@dataclass
class StackProfile:
    signals: set = field(default_factory=set)
    complete: bool = True
    files_seen: int = 0

    def has_any(self, wanted) -> bool:
        if not self.complete or not wanted:
            return True
        return any(w in self.signals for w in wanted)


def _list_files(repo: Path) -> tuple[list[str], bool]:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, timeout=60,
        )
        if r.returncode == 0:
            names = [n for n in r.stdout.decode("utf-8", "replace").split("\0") if n]
            names = [n for n in names if not any(p in _SKIP_DIRS for p in PurePosixPath(n).parts[:-1])]
            return names[:_MAX_FILES], len(names) <= _MAX_FILES
    except (OSError, subprocess.SubprocessError):
        pass
    out: list[str] = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".git")]
        rel = Path(root).relative_to(repo)
        for f in files:
            out.append((rel / f).as_posix() if str(rel) != "." else f)
            if len(out) > _MAX_FILES:
                return out[:_MAX_FILES], False
    return out, True


def _read(path: Path, limit: int = _MAX_FILE_BYTES) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def detect_stack(repo_path: str) -> StackProfile:
    repo = Path(repo_path)
    if not repo.is_dir():
        return StackProfile(complete=False)
    files, complete = _list_files(repo)
    found: set[str] = set()
    dockerfiles = 0
    manifests: list[str] = []
    sources: list[str] = []
    for rel in files:
        low = rel.lower()
        name = low.rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1]
        if name.endswith(".blade.php"):
            ext = ".blade"
        if name in ("dockerfile", "containerfile") or name.startswith("dockerfile.") \
                or name.endswith(".dockerfile"):
            dockerfiles += 1
        if name in _IAC_NAMES or ext in _IAC_EXT or name.startswith("dockerfile") \
                or any(("/" + low).find("/" + d) >= 0 for d in _IAC_DIRS):
            found.add("iac")
        if ext in _WEB_EXT:
            found.add("web")
        if ext in _TEMPLATE_EXT or "/templates/" in "/" + low or "/views/" in "/" + low:
            found.add("templates")
        if ext == ".proto":
            found.add("multiservice")
        if name in _MANIFESTS or name.endswith((".csproj", ".fsproj", ".vbproj")):
            manifests.append(rel)
        elif ext in _SOURCE_EXT or ext in _TEMPLATE_EXT:
            sources.append(rel)
    if dockerfiles >= 2:
        found.add("multiservice")
    for rel in manifests:
        text = _read(repo / rel, 2 * 1024 * 1024)
        for signal, pattern in _DEP_SIGNALS.items():
            if signal not in found and pattern.search(text):
                found.add(signal)
    for rel in files:
        low = rel.lower().rsplit("/", 1)[-1]
        if low in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            if _compose_services(_read(repo / rel)) >= 2:
                found.add("multiservice")
    budget = _MAX_SCAN_BYTES
    wanted = [s for s in _CONTENT_SIGNALS if s not in found]
    for rel in sources:
        if not wanted:
            break
        text = _read(repo / rel)
        budget -= len(text)
        if budget < 0:
            complete = False
            break
        for signal in list(wanted):
            if signal == "iac" and not rel.lower().endswith((".yaml", ".yml")):
                continue
            if _CONTENT_SIGNALS[signal].search(text):
                found.add(signal)
                wanted.remove(signal)
    return StackProfile(signals=found, complete=complete, files_seen=len(files))


def _compose_services(text: str) -> int:
    in_services = False
    indent = None
    count = 0
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if in_services:
            if not line.startswith((" ", "\t")):
                break
            lead = len(line) - len(line.lstrip())
            if indent is None:
                indent = lead
            if lead == indent and line.strip().endswith(":"):
                count += 1
    return count


def describe(signals) -> str:
    return " or ".join(SIGNAL_LABELS.get(s, s) for s in signals)
