"""
Casos controlados de vulnerabilidades desarrollados por el equipo.

OWASP Benchmark cubre sobre todo inyecciones y criptografía en aplicaciones
web clásicas, pero no contiene ejemplos de riesgos propios de APIs REST ni de
archivos de configuración de microservicios. Este módulo define plantillas
pequeñas (Spring Boot, FastAPI, YAML, Dockerfile, etc.) con una versión
vulnerable y otra segura para cada patrón, y las instancia variando nombres de
entidades, rutas y servicios.

Cada plantilla tiene un identificador propio que luego se usa como "grupo" al
particionar el dataset: todas las instancias de una misma plantilla caen en la
misma partición, de modo que el conjunto de prueba contiene plantillas que el
modelo nunca vio durante el entrenamiento.
"""

import random
import re

ENTIDADES = [
    ("Order", "order", "orders"),
    ("Invoice", "invoice", "invoices"),
    ("Account", "account", "accounts"),
    ("Ticket", "ticket", "tickets"),
    ("Payment", "payment", "payments"),
    ("Profile", "profile", "profiles"),
    ("Product", "product", "products"),
    ("Shipment", "shipment", "shipments"),
    ("Booking", "booking", "bookings"),
    ("Document", "document", "documents"),
]
BASES = ["/api", "/api/v1", "/v1", "/api/v2"]
IDS = ["id", "resourceId", "itemId"]
SERVICIOS = ["user-service", "order-service", "billing-service", "catalog-service",
             "inventory-service", "payment-service", "auth-service", "notification-service"]
PUERTOS = ["8080", "8081", "8000", "5000", "9090"]

# Versiones con vulnerabilidades públicas conocidas (CVE) y versiones vigentes
# a noviembre de 2026. Solo se usan para generar archivos de dependencias.
DEP_MAVEN_VULN = [
    ("org.apache.logging.log4j", "log4j-core", "2.14.1"),
    ("com.fasterxml.jackson.core", "jackson-databind", "2.9.8"),
    ("org.apache.commons", "commons-text", "1.9"),
    ("org.yaml", "snakeyaml", "1.33"),
    ("org.springframework", "spring-webmvc", "5.3.17"),
]
DEP_MAVEN_OK = [
    ("org.apache.logging.log4j", "log4j-core", "2.24.3"),
    ("com.fasterxml.jackson.core", "jackson-databind", "2.18.2"),
    ("org.apache.commons", "commons-text", "1.12.0"),
    ("org.yaml", "snakeyaml", "2.3"),
    ("org.springframework", "spring-webmvc", "6.2.1"),
]
DEP_PIP_VULN = ["PyYAML==5.3.1", "requests==2.19.1", "urllib3==1.24.1", "Jinja2==2.10",
                "Pillow==8.0.0", "fastapi==0.65.1", "Django==3.2.0", "cryptography==3.2"]
DEP_PIP_OK = ["PyYAML==6.0.2", "requests==2.32.3", "urllib3==2.2.3", "Jinja2==3.1.5",
              "Pillow==11.0.0", "fastapi==0.115.6", "Django==5.1.4", "cryptography==44.0.0"]


# ---------------------------------------------------------------------------
# Plantillas. Los marcadores @E@, @e@, @es@, @id@, @base@, @svc@ y @port@ se
# reemplazan al instanciar. Formato: (id, categoria, cwe, vulnerable, tipo, framework, codigo)
# ---------------------------------------------------------------------------

PLANTILLAS = []


def plantilla(pid, categoria, cwe, vulnerable, tipo, framework, codigo):
    PLANTILLAS.append(dict(plantilla=pid, categoria_vuln=categoria, cwe=cwe,
                           vulnerable=int(vulnerable), tipo_archivo=tipo,
                           framework=framework, codigo=codigo.strip("\n") + "\n"))


# --- BOLA: autorización a nivel de objeto (CWE-639) ------------------------

plantilla("bola-java-v1", "bola", "CWE-639", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    private final @E@Repository repository;

    public @E@Controller(@E@Repository repository) {
        this.repository = repository;
    }

    @GetMapping("/{@id@}")
    public ResponseEntity<@E@> get@E@(@PathVariable Long @id@) {
        return repository.findById(@id@)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
""")

plantilla("bola-java-v2", "bola", "CWE-639", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    @Autowired
    private @E@Service service;

    @DeleteMapping("/{@id@}")
    public ResponseEntity<Void> delete@E@(@PathVariable Long @id@, Principal principal) {
        // el usuario esta autenticado, pero no se verifica que sea el dueno
        service.deleteById(@id@);
        return ResponseEntity.noContent().build();
    }
}
""")

plantilla("bola-java-v3", "bola", "CWE-639", 1, "java", "spring", """
@RestController
public class @E@Controller {
    @Autowired
    private @E@Repository repo;

    @PutMapping("@base@/users/{userId}/@es@/{@id@}")
    public @E@ update@E@(@PathVariable Long userId, @PathVariable Long @id@,
                         @Valid @RequestBody @E@Request request) {
        @E@ entity = repo.findById(@id@).orElseThrow();
        entity.setDescription(request.getDescription());
        return repo.save(entity);
    }
}
""")

plantilla("bola-java-s1", "bola", "CWE-639", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    private final @E@Repository repository;

    public @E@Controller(@E@Repository repository) {
        this.repository = repository;
    }

    @GetMapping("/{@id@}")
    public ResponseEntity<@E@> get@E@(@PathVariable Long @id@,
                                      @AuthenticationPrincipal UserDetails user) {
        return repository.findByIdAndOwnerUsername(@id@, user.getUsername())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
""")

plantilla("bola-java-s2", "bola", "CWE-639", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    @Autowired
    private @E@Service service;

    @DeleteMapping("/{@id@}")
    public ResponseEntity<Void> delete@E@(@PathVariable Long @id@, Principal principal) {
        @E@ entity = service.findById(@id@);
        if (!entity.getOwner().equals(principal.getName())) {
            throw new AccessDeniedException("No autorizado");
        }
        service.deleteById(@id@);
        return ResponseEntity.noContent().build();
    }
}
""")

plantilla("bola-py-v1", "bola", "CWE-639", 1, "python", "fastapi", """
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .database import get_db
from .models import @E@

router = APIRouter(prefix="@base@/@es@")


@router.get("/{@id@}")
def get_@e@(@id@: int, db: Session = Depends(get_db)):
    @e@ = db.query(@E@).filter(@E@.id == @id@).first()
    if @e@ is None:
        raise HTTPException(status_code=404, detail="Not found")
    return @e@
""")

plantilla("bola-py-v2", "bola", "CWE-639", 1, "python", "fastapi", """
from fastapi import APIRouter, Depends
from .auth import get_current_user
from .database import get_db
from .models import @E@
from .schemas import @E@Update

router = APIRouter()


@router.put("@base@/@es@/{@id@}")
def update_@e@(@id@: int, data: @E@Update, db=Depends(get_db),
               current_user=Depends(get_current_user)):
    @e@ = db.get(@E@, @id@)
    @e@.description = data.description
    db.commit()
    return @e@
""")

plantilla("bola-py-s1", "bola", "CWE-639", 0, "python", "fastapi", """
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .auth import get_current_user
from .database import get_db
from .models import @E@

router = APIRouter(prefix="@base@/@es@")


@router.get("/{@id@}")
def get_@e@(@id@: int, db: Session = Depends(get_db),
            current_user=Depends(get_current_user)):
    @e@ = (db.query(@E@)
           .filter(@E@.id == @id@, @E@.owner_id == current_user.id)
           .first())
    if @e@ is None:
        raise HTTPException(status_code=404, detail="Not found")
    return @e@
""")

plantilla("bola-py-s2", "bola", "CWE-639", 0, "python", "fastapi", """
from fastapi import APIRouter, Depends, HTTPException
from .auth import get_current_user
from .database import get_db
from .models import @E@
from .schemas import @E@Update

router = APIRouter()


@router.put("@base@/@es@/{@id@}")
def update_@e@(@id@: int, data: @E@Update, db=Depends(get_db),
               current_user=Depends(get_current_user)):
    @e@ = db.get(@E@, @id@)
    if @e@ is None or @e@.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    @e@.description = data.description
    db.commit()
    return @e@
""")

# --- BFLA: autorización a nivel de función (CWE-285) -----------------------

plantilla("bfla-java-v1", "bfla", "CWE-285", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/admin/@es@")
public class Admin@E@Controller {
    @Autowired
    private @E@Service service;

    @DeleteMapping("/{@id@}")
    public ResponseEntity<Void> remove(@PathVariable Long @id@) {
        service.deleteById(@id@);
        return ResponseEntity.noContent().build();
    }
}
""")

plantilla("bfla-java-v2", "bfla", "CWE-285", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@ApprovalController {
    @Autowired
    private @E@Service service;

    @PostMapping("/{@id@}/approve")
    public @E@ approve(@PathVariable Long @id@, Authentication authentication) {
        // cualquier usuario autenticado puede aprobar
        return service.approve(@id@, authentication.getName());
    }
}
""")

plantilla("bfla-java-s1", "bfla", "CWE-285", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/admin/@es@")
public class Admin@E@Controller {
    @Autowired
    private @E@Service service;

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{@id@}")
    public ResponseEntity<Void> remove(@PathVariable Long @id@) {
        service.deleteById(@id@);
        return ResponseEntity.noContent().build();
    }
}
""")

plantilla("bfla-java-s2", "bfla", "CWE-285", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@ApprovalController {
    @Autowired
    private @E@Service service;

    @PostMapping("/{@id@}/approve")
    public ResponseEntity<@E@> approve(@PathVariable Long @id@, Authentication authentication) {
        boolean isManager = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_MANAGER"));
        if (!isManager) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(service.approve(@id@, authentication.getName()));
    }
}
""")

plantilla("bfla-py-v1", "bfla", "CWE-285", 1, "python", "fastapi", """
from fastapi import APIRouter, Depends
from .auth import get_current_user
from .database import get_db
from .models import @E@

router = APIRouter(prefix="@base@/admin")


@router.delete("/@es@/{@id@}", status_code=204)
def delete_@e@(@id@: int, db=Depends(get_db), user=Depends(get_current_user)):
    db.query(@E@).filter(@E@.id == @id@).delete()
    db.commit()
""")

plantilla("bfla-py-v2", "bfla", "CWE-285", 1, "python", "fastapi", """
from fastapi import APIRouter, Depends
from .database import get_db
from .models import User

router = APIRouter()


@router.post("@base@/users/{user_id}/role")
def change_role(user_id: int, role: str, db=Depends(get_db)):
    user = db.get(User, user_id)
    user.role = role
    db.commit()
    return {"status": "updated"}
""")

plantilla("bfla-py-s1", "bfla", "CWE-285", 0, "python", "fastapi", """
from fastapi import APIRouter, Depends
from .auth import require_role
from .database import get_db
from .models import @E@

router = APIRouter(prefix="@base@/admin")


@router.delete("/@es@/{@id@}", status_code=204)
def delete_@e@(@id@: int, db=Depends(get_db), user=Depends(require_role("admin"))):
    db.query(@E@).filter(@E@.id == @id@).delete()
    db.commit()
""")

plantilla("bfla-py-s2", "bfla", "CWE-285", 0, "python", "fastapi", """
from fastapi import APIRouter, Depends, HTTPException
from .auth import get_current_user
from .database import get_db
from .models import User

router = APIRouter()


@router.post("@base@/users/{user_id}/role")
def change_role(user_id: int, role: str, db=Depends(get_db),
                current_user=Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    user = db.get(User, user_id)
    user.role = role
    db.commit()
    return {"status": "updated"}
""")

# --- SSRF (CWE-918) --------------------------------------------------------

plantilla("ssrf-java-v1", "ssrf", "CWE-918", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@PreviewController {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/preview")
    public String preview(@RequestParam String url) {
        return restTemplate.getForObject(url, String.class);
    }
}
""")

plantilla("ssrf-java-v2", "ssrf", "CWE-918", 1, "java", "spring", """
@Service
public class @E@WebhookService {
    public void notify(@E@ @e@, String callbackUrl) throws IOException {
        URL target = new URL(callbackUrl);
        try (InputStream in = target.openStream()) {
            in.readAllBytes();
        }
    }
}
""")

plantilla("ssrf-java-s1", "ssrf", "CWE-918", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@PreviewController {
    private static final Set<String> ALLOWED_HOSTS = Set.of("cdn.example.com", "images.example.com");
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/preview")
    public ResponseEntity<String> preview(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            return ResponseEntity.badRequest().body("Host not allowed");
        }
        return ResponseEntity.ok(restTemplate.getForObject(uri, String.class));
    }
}
""")

plantilla("ssrf-java-s2", "ssrf", "CWE-918", 0, "java", "spring", """
@Service
public class @E@Client {
    private static final String BASE_URL = "http://@svc@:@port@";
    private final RestTemplate restTemplate;

    public @E@Client(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public @E@ fetch(Long @id@) {
        return restTemplate.getForObject(BASE_URL + "/@es@/{id}", @E@.class, @id@);
    }
}
""")

plantilla("ssrf-py-v1", "ssrf", "CWE-918", 1, "python", "fastapi", """
import requests
from fastapi import APIRouter

router = APIRouter()


@router.get("@base@/@es@/preview")
def preview(url: str):
    response = requests.get(url, timeout=5)
    return {"status": response.status_code, "body": response.text[:500]}
""")

plantilla("ssrf-py-v2", "ssrf", "CWE-918", 1, "python", "fastapi", """
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class Webhook(BaseModel):
    callback_url: str


@router.post("@base@/@es@/webhook")
async def register_webhook(hook: Webhook):
    async with httpx.AsyncClient() as client:
        await client.post(hook.callback_url, json={"event": "registered"})
    return {"ok": True}
""")

plantilla("ssrf-py-s1", "ssrf", "CWE-918", 0, "python", "fastapi", """
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException

router = APIRouter()
ALLOWED_HOSTS = {"cdn.example.com", "images.example.com"}


@router.get("@base@/@es@/preview")
def preview(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="Host not allowed")
    response = requests.get(url, timeout=5, allow_redirects=False)
    return {"status": response.status_code}
""")

plantilla("ssrf-py-s2", "ssrf", "CWE-918", 0, "python", "fastapi", """
import httpx

@E@_SERVICE_URL = "http://@svc@:@port@"


async def fetch_@e@(@id@: int):
    async with httpx.AsyncClient(base_url=@E@_SERVICE_URL, timeout=5) as client:
        response = await client.get(f"/@es@/{@id@}")
        response.raise_for_status()
        return response.json()
""")

# --- Asignación masiva (CWE-915) -------------------------------------------

plantilla("mass-java-v1", "asignacion_masiva", "CWE-915", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    @Autowired
    private @E@Repository repository;

    @PutMapping("/{@id@}")
    public @E@ update(@PathVariable Long @id@, @RequestBody @E@ body) {
        body.setId(@id@);
        return repository.save(body);
    }
}
""")

plantilla("mass-java-v2", "asignacion_masiva", "CWE-915", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/users")
public class UserController {
    @Autowired
    private UserRepository repository;

    @PatchMapping("/{@id@}")
    public User patch(@PathVariable Long @id@, @RequestBody Map<String, Object> changes) {
        User user = repository.findById(@id@).orElseThrow();
        BeanWrapper wrapper = new BeanWrapperImpl(user);
        changes.forEach(wrapper::setPropertyValue);
        return repository.save(user);
    }
}
""")

plantilla("mass-java-s1", "asignacion_masiva", "CWE-915", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    @Autowired
    private @E@Repository repository;

    @PutMapping("/{@id@}")
    public @E@ update(@PathVariable Long @id@, @Valid @RequestBody @E@UpdateDto dto) {
        @E@ entity = repository.findById(@id@).orElseThrow();
        entity.setName(dto.name());
        entity.setDescription(dto.description());
        return repository.save(entity);
    }
}
""")

plantilla("mass-java-s2", "asignacion_masiva", "CWE-915", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/users")
public class UserController {
    @Autowired
    private UserRepository repository;

    @PatchMapping("/{@id@}")
    public User patch(@PathVariable Long @id@, @Valid @RequestBody UserProfileDto dto) {
        User user = repository.findById(@id@).orElseThrow();
        BeanUtils.copyProperties(dto, user, "id", "role", "balance", "verified");
        return repository.save(user);
    }
}
""")

plantilla("mass-py-v1", "asignacion_masiva", "CWE-915", 1, "python", "fastapi", """
from fastapi import APIRouter, Body, Depends
from .database import get_db
from .models import @E@

router = APIRouter()


@router.put("@base@/@es@/{@id@}")
def update_@e@(@id@: int, payload: dict = Body(...), db=Depends(get_db)):
    @e@ = db.get(@E@, @id@)
    for key, value in payload.items():
        setattr(@e@, key, value)
    db.commit()
    return @e@
""")

plantilla("mass-py-v2", "asignacion_masiva", "CWE-915", 1, "python", "fastapi", """
from fastapi import APIRouter, Depends, Request
from .database import get_db
from .models import User

router = APIRouter()


@router.post("@base@/users")
async def register(request: Request, db=Depends(get_db)):
    data = await request.json()
    user = User(**data)
    db.add(user)
    db.commit()
    return user
""")

plantilla("mass-py-s1", "asignacion_masiva", "CWE-915", 0, "python", "fastapi", """
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from .database import get_db
from .models import @E@

router = APIRouter()


class @E@Update(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str | None = None


@router.put("@base@/@es@/{@id@}")
def update_@e@(@id@: int, payload: @E@Update, db=Depends(get_db)):
    @e@ = db.get(@E@, @id@)
    @e@.name = payload.name
    @e@.description = payload.description
    db.commit()
    return @e@
""")

plantilla("mass-py-s2", "asignacion_masiva", "CWE-915", 0, "python", "fastapi", """
from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr
from .database import get_db
from .models import User

router = APIRouter()


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


@router.post("@base@/users")
def register(data: UserCreate, db=Depends(get_db)):
    user = User(username=data.username, email=data.email,
                password_hash=hash_password(data.password), role="user")
    db.add(user)
    db.commit()
    return {"id": user.id}
""")

# --- Consumo ilimitado de recursos (CWE-770) -------------------------------

plantilla("res-java-v1", "consumo_recursos", "CWE-770", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    @Autowired
    private @E@Repository repository;

    @GetMapping
    public List<@E@> list() {
        return repository.findAll();
    }
}
""")

plantilla("res-java-v2", "consumo_recursos", "CWE-770", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    @Autowired
    private @E@Repository repository;

    @GetMapping
    public Page<@E@> list(@RequestParam(defaultValue = "0") int page,
                          @RequestParam(defaultValue = "20") int size) {
        return repository.findAll(PageRequest.of(page, size));
    }
}
""")

plantilla("res-java-s1", "consumo_recursos", "CWE-770", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    private static final int MAX_PAGE_SIZE = 100;

    @Autowired
    private @E@Repository repository;

    @GetMapping
    public Page<@E@> list(@RequestParam(defaultValue = "0") int page,
                          @RequestParam(defaultValue = "20") int size) {
        int safeSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        return repository.findAll(PageRequest.of(page, safeSize));
    }
}
""")

plantilla("res-java-s2", "consumo_recursos", "CWE-770", 0, "java", "spring", """
@Validated
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    @Autowired
    private @E@Repository repository;

    @GetMapping
    public Page<@E@> list(@RequestParam(defaultValue = "0") @Min(0) int page,
                          @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        return repository.findAll(PageRequest.of(page, size));
    }
}
""")

plantilla("res-py-v1", "consumo_recursos", "CWE-770", 1, "python", "fastapi", """
from fastapi import APIRouter, Depends
from .database import get_db
from .models import @E@

router = APIRouter()


@router.get("@base@/@es@")
def list_@es@(db=Depends(get_db)):
    return db.query(@E@).all()
""")

plantilla("res-py-v2", "consumo_recursos", "CWE-770", 1, "python", "fastapi", """
from fastapi import APIRouter, Depends
from .database import get_db
from .models import @E@

router = APIRouter()


@router.get("@base@/@es@")
def list_@es@(skip: int = 0, limit: int = 50, db=Depends(get_db)):
    return db.query(@E@).offset(skip).limit(limit).all()
""")

plantilla("res-py-s1", "consumo_recursos", "CWE-770", 0, "python", "fastapi", """
from fastapi import APIRouter, Depends, Query
from .database import get_db
from .models import @E@

router = APIRouter()


@router.get("@base@/@es@")
def list_@es@(skip: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100),
              db=Depends(get_db)):
    return db.query(@E@).offset(skip).limit(limit).all()
""")

plantilla("res-py-s2", "consumo_recursos", "CWE-770", 0, "python", "fastapi", """
from fastapi import APIRouter, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from .database import get_db
from .models import @E@

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
MAX_PAGE_SIZE = 100


@router.get("@base@/@es@")
@limiter.limit("30/minute")
def list_@es@(request: Request, skip: int = 0, limit: int = 20, db=Depends(get_db)):
    limit = min(max(limit, 1), MAX_PAGE_SIZE)
    return db.query(@E@).offset(skip).limit(limit).all()
""")

# --- Autenticación (CWE-347, CWE-798, CWE-307) -----------------------------

plantilla("auth-java-v1", "autenticacion", "CWE-347", 1, "java", "spring", """
@Component
public class JwtTokenFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            String payload = new String(Base64.getUrlDecoder().decode(token.split("\\\\.")[1]));
            Map<String, Object> claims = new ObjectMapper().readValue(payload, Map.class);
            request.setAttribute("user", claims.get("sub"));
        }
        chain.doFilter(request, response);
    }
}
""")

plantilla("auth-java-v2", "autenticacion", "CWE-798", 1, "java", "spring", """
@Service
public class TokenService {
    private static final String JWT_SECRET = "@svc@-secret-2024";

    public String createToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET)
                .compact();
    }
}
""")

plantilla("auth-java-v3", "autenticacion", "CWE-307", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/auth")
public class LoginController {
    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        if (!authService.checkPassword(request.getUsername(), request.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(authService.issueToken(request.getUsername()));
    }
}
""")

plantilla("auth-java-s1", "autenticacion", "CWE-347", 0, "java", "spring", """
@Component
public class JwtTokenFilter extends OncePerRequestFilter {
    private final Key signingKey;

    public JwtTokenFilter(@Value("${jwt.secret}") String secret) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            Claims claims = Jwts.parserBuilder().setSigningKey(signingKey).build()
                    .parseClaimsJws(header.substring(7)).getBody();
            request.setAttribute("user", claims.getSubject());
        }
        chain.doFilter(request, response);
    }
}
""")

plantilla("auth-java-s2", "autenticacion", "CWE-798", 0, "java", "spring", """
@Service
public class TokenService {
    private final Key key;

    public TokenService(@Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + 900000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
""")

plantilla("auth-java-s3", "autenticacion", "CWE-307", 0, "java", "spring", """
@RestController
@RequestMapping("@base@/auth")
public class LoginController {
    @Autowired
    private AuthService authService;
    @Autowired
    private LoginAttemptService attempts;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        if (attempts.isBlocked(request.getUsername())) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build();
        }
        if (!authService.checkPassword(request.getUsername(), request.getPassword())) {
            attempts.registerFailure(request.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        attempts.reset(request.getUsername());
        return ResponseEntity.ok(authService.issueToken(request.getUsername()));
    }
}
""")

plantilla("auth-py-v1", "autenticacion", "CWE-347", 1, "python", "fastapi", """
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, options={"verify_signature": False})
    if "sub" not in payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload["sub"]
""")

plantilla("auth-py-v2", "autenticacion", "CWE-798", 1, "python", "fastapi", """
from datetime import datetime, timedelta

import jwt

SECRET_KEY = "@svc@-dev-key"
ALGORITHM = "HS256"


def create_access_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=12)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
""")

plantilla("auth-py-v3", "autenticacion", "CWE-307", 1, "python", "fastapi", """
from fastapi import APIRouter, HTTPException
from .schemas import LoginRequest
from .security import create_access_token, verify_password
from .users import get_user

router = APIRouter(prefix="@base@/auth")


@router.post("/login")
def login(data: LoginRequest):
    user = get_user(data.username)
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_access_token(user.username)}
""")

plantilla("auth-py-s1", "autenticacion", "CWE-347", 0, "python", "fastapi", """
import os

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = os.environ["JWT_SECRET"]


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload["sub"]
""")

plantilla("auth-py-s2", "autenticacion", "CWE-798", 0, "python", "fastapi", """
import os
from datetime import datetime, timedelta, timezone

import jwt

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"


def create_access_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
""")

plantilla("auth-py-s3", "autenticacion", "CWE-307", 0, "python", "fastapi", """
from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from .schemas import LoginRequest
from .security import create_access_token, verify_password
from .users import get_user

router = APIRouter(prefix="@base@/auth")
limiter = Limiter(key_func=get_remote_address)


@router.post("/login")
@limiter.limit("5/minute")
def login(request: Request, data: LoginRequest):
    user = get_user(data.username)
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_access_token(user.username)}
""")

# --- Manejo de excepciones (CWE-209, CWE-755) ------------------------------

plantilla("exc-java-v1", "manejo_excepciones", "CWE-209", 1, "java", "spring", """
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handle(Exception ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("error", ex.getMessage());
        body.put("trace", Arrays.toString(ex.getStackTrace()));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
""")

plantilla("exc-java-v2", "manejo_excepciones", "CWE-209", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@Controller {
    @Autowired
    private @E@Service service;

    @GetMapping("/{@id@}")
    public ResponseEntity<?> get(@PathVariable Long @id@) {
        try {
            return ResponseEntity.ok(service.findById(@id@));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Error: " + e.toString());
        }
    }
}
""")

plantilla("exc-java-v3", "manejo_excepciones", "CWE-755", 1, "java", "spring", """
@Service
public class @E@SyncService {
    @Autowired
    private @E@Client client;

    public boolean sync(Long @id@) {
        try {
            client.push(@id@);
        } catch (Exception e) {
        }
        return true;
    }
}
""")

plantilla("exc-java-s1", "manejo_excepciones", "CWE-209", 0, "java", "spring", """
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handle(Exception ex) {
        String errorId = UUID.randomUUID().toString();
        log.error("Unhandled error {}", errorId, ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Internal error", "errorId", errorId));
    }
}
""")

plantilla("exc-java-s2", "manejo_excepciones", "CWE-755", 0, "java", "spring", """
@Service
public class @E@SyncService {
    private static final Logger log = LoggerFactory.getLogger(@E@SyncService.class);
    @Autowired
    private @E@Client client;

    public boolean sync(Long @id@) {
        try {
            client.push(@id@);
            return true;
        } catch (RestClientException e) {
            log.warn("Sync failed for @e@ {}", @id@);
            return false;
        }
    }
}
""")

plantilla("exc-py-v1", "manejo_excepciones", "CWE-209", 1, "python", "fastapi", """
import traceback

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="@svc@")


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    return JSONResponse(status_code=500,
                        content={"error": str(exc), "trace": traceback.format_exc()})
""")

plantilla("exc-py-v2", "manejo_excepciones", "CWE-209", 1, "python", "fastapi", """
from fastapi import APIRouter, Depends, HTTPException
from .database import get_db
from .services import @e@_service

router = APIRouter()


@router.get("@base@/@es@/{@id@}")
def get_@e@(@id@: int, db=Depends(get_db)):
    try:
        return @e@_service.get(db, @id@)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e!r}")
""")

plantilla("exc-py-v3", "manejo_excepciones", "CWE-755", 1, "python", "fastapi", """
from .clients import @e@_client


def sync_@e@(@id@: int) -> bool:
    try:
        @e@_client.push(@id@)
    except Exception:
        pass
    return True
""")

plantilla("exc-py-s1", "manejo_excepciones", "CWE-209", 0, "python", "fastapi", """
import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="@svc@")
logger = logging.getLogger(__name__)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())
    logger.exception("Unhandled error %s", error_id)
    return JSONResponse(status_code=500, content={"error": "Internal error", "error_id": error_id})
""")

plantilla("exc-py-s2", "manejo_excepciones", "CWE-755", 0, "python", "fastapi", """
import logging

import httpx
from .clients import @e@_client

logger = logging.getLogger(__name__)


def sync_@e@(@id@: int) -> bool:
    try:
        @e@_client.push(@id@)
        return True
    except httpx.HTTPError:
        logger.warning("Sync failed for @e@ %s", @id@)
        return False
""")

# --- Registro y monitoreo (CWE-532, CWE-117, CWE-778) ----------------------

plantilla("log-java-v1", "registro", "CWE-532", 1, "java", "spring", """
@Service
public class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    public boolean login(String username, String password) {
        log.info("Login attempt user=" + username + " password=" + password);
        return userRepository.matches(username, password);
    }
}
""")

plantilla("log-java-v2", "registro", "CWE-117", 1, "java", "spring", """
@RestController
@RequestMapping("@base@/@es@")
public class @E@SearchController {
    private static final Logger log = LoggerFactory.getLogger(@E@SearchController.class);

    @GetMapping("/search")
    public List<@E@> search(@RequestParam String q) {
        log.info("Search requested: " + q);
        return service.search(q);
    }
}
""")

plantilla("log-java-v3", "registro", "CWE-778", 1, "java", "spring", """
@Service
public class AuthService {
    public Optional<String> authenticate(String username, String password) {
        User user = userRepository.findByUsername(username);
        if (user == null || !encoder.matches(password, user.getPasswordHash())) {
            return Optional.empty();
        }
        return Optional.of(tokenService.createToken(username));
    }
}
""")

plantilla("log-java-s1", "registro", "CWE-532", 0, "java", "spring", """
@Service
public class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    public boolean login(String username, String password) {
        boolean ok = userRepository.matches(username, password);
        log.info("Login attempt user={} success={}", sanitize(username), ok);
        return ok;
    }
}
""")

plantilla("log-java-s2", "registro", "CWE-778", 0, "java", "spring", """
@Service
public class AuthService {
    private static final Logger audit = LoggerFactory.getLogger("SECURITY_AUDIT");

    public Optional<String> authenticate(String username, String password, String clientIp) {
        User user = userRepository.findByUsername(username);
        if (user == null || !encoder.matches(password, user.getPasswordHash())) {
            audit.warn("event=login_failed user={} ip={}", sanitize(username), clientIp);
            return Optional.empty();
        }
        audit.info("event=login_success user={} ip={}", sanitize(username), clientIp);
        return Optional.of(tokenService.createToken(username));
    }
}
""")

plantilla("log-py-v1", "registro", "CWE-532", 1, "python", "fastapi", """
import logging

logger = logging.getLogger(__name__)


def login(username: str, password: str) -> bool:
    logger.info(f"login attempt user={username} password={password}")
    return check_credentials(username, password)
""")

plantilla("log-py-v2", "registro", "CWE-117", 1, "python", "fastapi", """
import logging

from fastapi import APIRouter

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("@base@/@es@/search")
def search(q: str):
    logger.info("search requested: " + q)
    return search_@es@(q)
""")

plantilla("log-py-v3", "registro", "CWE-778", 1, "python", "fastapi", """
from fastapi import APIRouter, HTTPException
from .security import verify_password
from .users import get_user

router = APIRouter()


@router.post("@base@/auth/login")
def login(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": issue_token(user)}
""")

plantilla("log-py-s1", "registro", "CWE-532", 0, "python", "fastapi", """
import logging

logger = logging.getLogger(__name__)


def login(username: str, password: str) -> bool:
    ok = check_credentials(username, password)
    logger.info("login attempt user=%s success=%s", username.replace("\\n", ""), ok)
    return ok
""")

plantilla("log-py-s2", "registro", "CWE-778", 0, "python", "fastapi", """
import logging

from fastapi import APIRouter, HTTPException, Request
from .security import verify_password
from .users import get_user

router = APIRouter()
audit = logging.getLogger("security.audit")


@router.post("@base@/auth/login")
def login(request: Request, username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.password_hash):
        audit.warning("event=login_failed user=%s ip=%s", username, request.client.host)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    audit.info("event=login_success user=%s", username)
    return {"access_token": issue_token(user)}
""")

# --- Configuración insegura (CWE-16, CWE-942, CWE-489, CWE-250) -----------

plantilla("cfg-yml-v1", "configuracion", "CWE-16", 1, "yml", "spring", """
server:
  port: @port@
  error:
    include-stacktrace: always
    include-message: always
spring:
  application:
    name: @svc@
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    env:
      show-values: ALWAYS
""")

plantilla("cfg-yml-s1", "configuracion", "CWE-16", 0, "yml", "spring", """
server:
  port: @port@
  error:
    include-stacktrace: never
    include-message: never
spring:
  application:
    name: @svc@
management:
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      show-details: when-authorized
""")

plantilla("cfg-props-v1", "configuracion", "CWE-489", 1, "properties", "spring", """
spring.application.name=@svc@
server.port=@port@
debug=true
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=true
logging.level.root=DEBUG
spring.jpa.show-sql=true
""")

plantilla("cfg-props-s1", "configuracion", "CWE-489", 0, "properties", "spring", """
spring.application.name=@svc@
server.port=@port@
debug=false
spring.h2.console.enabled=false
logging.level.root=INFO
spring.jpa.show-sql=false
""")

plantilla("cfg-cors-java-v1", "configuracion", "CWE-942", 1, "java", "spring", """
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns("*")
                .allowedMethods("*")
                .allowCredentials(true);
    }
}
""")

plantilla("cfg-cors-java-s1", "configuracion", "CWE-942", 0, "java", "spring", """
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("@base@/**")
                .allowedOrigins("https://app.example.com")
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowCredentials(true);
    }
}
""")

plantilla("cfg-cors-py-v1", "configuracion", "CWE-942", 1, "python", "fastapi", """
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="@svc@", debug=True)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=@port@, reload=True)
""")

plantilla("cfg-cors-py-s1", "configuracion", "CWE-942", 0, "python", "fastapi", """
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="@svc@", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "https://app.example.com").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
""")

plantilla("cfg-docker-v1", "configuracion", "CWE-250", 1, "dockerfile", "docker", """
FROM python:latest
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
ENV DEBUG=1
EXPOSE @port@ 22
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "@port@", "--reload"]
""")

plantilla("cfg-docker-v2", "configuracion", "CWE-250", 1, "dockerfile", "docker", """
FROM openjdk:latest
COPY target/@svc@.jar /app.jar
USER root
EXPOSE @port@
ENTRYPOINT ["java", "-jar", "/app.jar"]
""")

plantilla("cfg-docker-s1", "configuracion", "CWE-250", 0, "dockerfile", "docker", """
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home appuser
USER appuser
EXPOSE @port@
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "@port@"]
""")

plantilla("cfg-docker-s2", "configuracion", "CWE-250", 0, "dockerfile", "docker", """
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app
COPY target/@svc@.jar /app/app.jar
USER app
EXPOSE @port@
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
""")

plantilla("cfg-compose-v1", "configuracion", "CWE-16", 1, "compose", "docker", """
services:
  @svc@:
    build: ./@svc@
    privileged: true
    ports:
      - "@port@:@port@"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  db:
    image: postgres:latest
    ports:
      - "5432:5432"
""")

plantilla("cfg-compose-s1", "configuracion", "CWE-16", 0, "compose", "docker", """
services:
  @svc@:
    build: ./@svc@
    read_only: true
    security_opt:
      - no-new-privileges:true
    ports:
      - "@port@:@port@"
    networks: [backend]
  db:
    image: postgres:16.4
    networks: [backend]
networks:
  backend:
    internal: true
""")

# --- Credenciales embebidas en configuración (CWE-798) ---------------------

plantilla("sec-yml-v1", "credenciales", "CWE-798", 1, "yml", "spring", """
spring:
  application:
    name: @svc@
  datasource:
    url: jdbc:postgresql://db:5432/@e@db
    username: admin
    password: Admin123!
jwt:
  secret: my-super-secret-key-@e@
""")

plantilla("sec-yml-s1", "credenciales", "CWE-798", 0, "yml", "spring", """
spring:
  application:
    name: @svc@
  datasource:
    url: jdbc:postgresql://db:5432/@e@db
    username: ${DB_USER}
    password: ${DB_PASSWORD}
jwt:
  secret: ${JWT_SECRET}
""")

plantilla("sec-compose-v1", "credenciales", "CWE-798", 1, "compose", "docker", """
services:
  @svc@:
    build: ./@svc@
    environment:
      DB_PASSWORD: postgres123
      API_KEY: sk_live_@e@_51HxYz
  db:
    image: postgres:16.4
    environment:
      POSTGRES_PASSWORD: postgres123
""")

plantilla("sec-compose-s1", "credenciales", "CWE-798", 0, "compose", "docker", """
services:
  @svc@:
    build: ./@svc@
    env_file: .env
    secrets:
      - db_password
  db:
    image: postgres:16.4
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
secrets:
  db_password:
    file: ./secrets/db_password.txt
""")

plantilla("sec-props-v1", "credenciales", "CWE-798", 1, "properties", "spring", """
spring.application.name=@svc@
spring.datasource.url=jdbc:mysql://db:3306/@e@db
spring.datasource.username=root
spring.datasource.password=root1234
app.api-key=AKIA@E@EXAMPLE7
""")

plantilla("sec-props-s1", "credenciales", "CWE-798", 0, "properties", "spring", """
spring.application.name=@svc@
spring.datasource.url=jdbc:mysql://db:3306/@e@db
spring.datasource.username=${DB_USER}
spring.datasource.password=${DB_PASSWORD}
app.api-key=${API_KEY}
""")


# ---------------------------------------------------------------------------
# Archivos de dependencias (CWE-1104). Se generan aparte porque el contenido
# depende de una selección aleatoria de librerías y versiones.
# ---------------------------------------------------------------------------

def _pom(svc, deps):
    bloques = "\n".join(
        f"""        <dependency>
            <groupId>{g}</groupId>
            <artifactId>{a}</artifactId>
            <version>{v}</version>
        </dependency>""" for g, a, v in deps)
    return f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>{svc}</artifactId>
    <version>1.0.0</version>
    <dependencies>
{bloques}
    </dependencies>
</project>
"""


def _requirements(deps, extra):
    return "\n".join(sorted(deps + extra)) + "\n"


def casos_dependencias(rng, instancias):
    casos = []
    neutras = ["uvicorn==0.32.1", "sqlalchemy==2.0.36", "pydantic==2.10.3", "httpx==0.28.1"]
    for i in range(instancias):
        svc = rng.choice(SERVICIOS)
        k = rng.randint(2, 3)
        idx = rng.sample(range(len(DEP_MAVEN_VULN)), k)
        casos.append(dict(plantilla="dep-pom-v1", vulnerable=1, tipo_archivo="pom",
                          codigo=_pom(svc, [DEP_MAVEN_VULN[j] for j in idx])))
        casos.append(dict(plantilla="dep-pom-s1", vulnerable=0, tipo_archivo="pom",
                          codigo=_pom(svc, [DEP_MAVEN_OK[j] for j in idx])))
        idx = rng.sample(range(len(DEP_PIP_VULN)), rng.randint(2, 4))
        extra = rng.sample(neutras, 2)
        casos.append(dict(plantilla="dep-req-v1", vulnerable=1, tipo_archivo="requirements",
                          codigo=_requirements([DEP_PIP_VULN[j] for j in idx], extra)))
        casos.append(dict(plantilla="dep-req-s1", vulnerable=0, tipo_archivo="requirements",
                          codigo=_requirements([DEP_PIP_OK[j] for j in idx], extra)))
        # cada archivo de dependencias es una combinación aleatoria distinta,
        # por eso el grupo de partición es la instancia y no la plantilla
        for c in casos[-4:]:
            c["grupo"] = f"{c['plantilla']}#{i}"
    for c in casos:
        c.update(categoria_vuln="dependencias", cwe="CWE-1104",
                 framework="maven" if c["tipo_archivo"] == "pom" else "pip")
    return casos


_MARCADOR = re.compile(r"@(E|e|es|id|base|svc|port)@")

LENGUAJE_POR_TIPO = {"java": "java", "python": "python"}


def generar(instancias=5, semilla=42):
    """Devuelve una lista de dicts, uno por caso controlado instanciado."""
    rng = random.Random(semilla)
    casos = []
    # Los valores se asignan recorriendo cada lista en ciclo, con un contador
    # independiente para plantillas vulnerables y seguras. Así ambas clases
    # reciben la misma distribución de entidades, rutas y servicios y ninguno de
    # esos nombres puede asociarse con la etiqueta. Al usar longitudes de lista
    # distintas (10, 3, 4, 8, 5) las combinaciones no se repiten en un mismo ciclo.
    contador = {0: 0, 1: 0}
    for p in PLANTILLAS:
        for _ in range(instancias):
            k = contador[p["vulnerable"]]
            contador[p["vulnerable"]] += 1
            ent = ENTIDADES[k % len(ENTIDADES)]
            valores = {"E": ent[0], "e": ent[1], "es": ent[2],
                       "id": IDS[k % len(IDS)], "base": BASES[k % len(BASES)],
                       "svc": SERVICIOS[k % len(SERVICIOS)], "port": PUERTOS[k % len(PUERTOS)]}
            codigo = _MARCADOR.sub(lambda m: valores[m.group(1)], p["codigo"])
            if p["tipo_archivo"] == "java":
                paquete = valores["svc"].replace("-service", "")
                codigo = f"package com.example.{paquete};\n\n" + codigo
            casos.append({**p, "codigo": codigo})
    casos.extend(casos_dependencias(rng, instancias + 2))
    for c in casos:
        c["lenguaje"] = LENGUAJE_POR_TIPO.get(c["tipo_archivo"], "config")
        c.setdefault("grupo", c["plantilla"])
    return casos
