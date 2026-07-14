// ══════════════════════════════════════════════════════════
// LUMINO — Serveur de vérification Delta (Node.js)
// Remplace l'Edge Function Supabase, car @dfinity/agent ne
// fonctionne pas dans l'environnement Deno de Supabase.
// Fait exactement la même chose, mais en Node.js classique où
// cette bibliothèque est prévue pour fonctionner.
// ══════════════════════════════════════════════════════════

require("isomorphic-fetch");
const express = require("express");
const crypto = require("crypto");
const { HttpAgent, Actor } = require("@dfinity/agent");
const { IDL } = require("@dfinity/candid");

const app = express();
app.use(express.json());

// CORS ouvert (n'importe quel front peut appeler ce service)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, apikey");
  res.header("Access-Control-Allow-Methods", "POST, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

const APP_ID = 40; // App ID Lumino sur DApp Square
const ICP_HOST = "https://icp-api.io";

// Candid IDL minimal — uniquement getDAppAcctInfo
const idlFactory = ({ IDL }) => {
  const IdentityToken = IDL.Record({ did: IDL.Text, token: IDL.Text });
  const RoleVariant = IDL.Variant({
    miner: IDL.Null,
    ambassador: IDL.Null,
    verifier: IDL.Null,
    developer: IDL.Null,
  });
  const RoleEntry = IDL.Tuple(RoleVariant, IDL.Int);
  const DAppAcctInfo = IDL.Record({
    uid: IDL.Nat,
    nickname: IDL.Opt(IDL.Text),
    cCode: IDL.Opt(IDL.Text),
    roles: IDL.Opt(IDL.Vec(RoleEntry)),
    avatar: IDL.Opt(IDL.Text),
    avatarSrc: IDL.Opt(IDL.Text),
  });
  return IDL.Service({
    getDAppAcctInfo: IDL.Func([IdentityToken, IDL.Nat], [DAppAcctInfo], ["query"]),
  });
};

// Un champ "opt" @dfinity arrive sous forme de tableau : [] (absent) ou [valeur]
function unwrapOpt(v) {
  return Array.isArray(v) && v.length ? v[0] : null;
}

async function verifyDeltaToken(accCanisterId, dAppIdentToken) {
  const agent = new HttpAgent({ host: ICP_HOST });
  const actor = Actor.createActor(idlFactory, { agent, canisterId: accCanisterId });
  return await actor.getDAppAcctInfo(dAppIdentToken, APP_ID);
}

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function signJwtHS256(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = base64url(JSON.stringify(header));
  const encPayload = base64url(JSON.stringify(payload));
  const data = `${encHeader}.${encPayload}`;
  const sig = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  return `${data}.${sig}`;
}

app.post("/verify-delta-auth", async (req, res) => {
  try {
    const { accCanisterId, dAppIdentToken } = req.body;
    if (!accCanisterId || !dAppIdentToken?.did || !dAppIdentToken?.token) {
      return res.status(400).json({ error: "Requête invalide" });
    }

    console.log("[verify-delta-auth] Requête reçue — accCanisterId:", accCanisterId, "did:", dAppIdentToken.did);

    const acctInfo = await verifyDeltaToken(accCanisterId, dAppIdentToken);
    console.log("[verify-delta-auth] Vérification canister réussie ✓", acctInfo);

    const jwtSecret = process.env.JWT_SIGNING_SECRET;
    if (!jwtSecret) {
      return res.status(500).json({ error: "JWT_SIGNING_SECRET non configuré" });
    }

    const now = Math.floor(Date.now() / 1000);
    const jwt = signJwtHS256(
      {
        sub: dAppIdentToken.did,
        did: dAppIdentToken.did,
        role: "authenticated",
        iat: now,
        exp: now + 60 * 60,
      },
      jwtSecret
    );

    res.json({
      jwt,
      did: dAppIdentToken.did,
      nickname: unwrapOpt(acctInfo?.nickname),
      avatarSrc: unwrapOpt(acctInfo?.avatarSrc),
      uid: acctInfo?.uid !== undefined && acctInfo?.uid !== null ? Number(acctInfo.uid) : null,
    });
  } catch (e) {
    console.error("[verify-delta-auth] Échec de vérification:", e.message || String(e));
    res.status(401).json({ error: "Vérification échouée", details: e.message || String(e) });
  }
});

// ══════════════════════════════════════════════════════════
// Vérification publique de certificat — accessible sans connexion,
// utile par exemple pour qu'un employeur vérifie un certificat.
// ══════════════════════════════════════════════════════════
const SUPABASE_URL = "https://qwsqxusmjxcmufllcvww.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_ygofuXiyqVT-bT9he8Nhzg_2xRKrc6b";

app.get("/verify-certificate", async (req, res) => {
  const certId = req.query.id;
  if (!certId) {
    return res.status(400).send(renderCertPage(false, null, null));
  }
  try {
    const enrRes = await fetch(
      `${SUPABASE_URL}/rest/v1/enrollments?certificate_id=eq.${encodeURIComponent(certId)}&status=eq.completed&select=*`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: "Bearer " + SUPABASE_ANON_KEY } }
    );
    const enrData = await enrRes.json();
    if (!Array.isArray(enrData) || !enrData.length) {
      return res.status(404).send(renderCertPage(false, null, null));
    }
    const enr = enrData[0];

    const courseRes = await fetch(
      `${SUPABASE_URL}/rest/v1/courses?id=eq.${encodeURIComponent(enr.course_id)}&select=title,instructor_nickname`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: "Bearer " + SUPABASE_ANON_KEY } }
    );
    const courseData = await courseRes.json();
    const course = Array.isArray(courseData) && courseData[0] ? courseData[0] : null;

    const userRes = await fetch(
      `${SUPABASE_URL}/rest/v1/users?did=eq.${encodeURIComponent(enr.student_did)}&select=nickname`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: "Bearer " + SUPABASE_ANON_KEY } }
    );
    const userData = await userRes.json();
    const student = Array.isArray(userData) && userData[0] ? userData[0] : null;

    res.send(renderCertPage(true, enr, { course, student }));
  } catch (e) {
    console.error("[verify-certificate] Erreur:", e.message || String(e));
    res.status(500).send(renderCertPage(false, null, null));
  }
});

function renderCertPage(valid, enr, extra) {
  const style = `body{font-family:sans-serif;background:#0A0118;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
    .card{background:#1a0a2e;border:1px solid rgba(255,184,0,.3);border-radius:16px;padding:32px;max-width:480px;text-align:center}
    h1{color:#FFB800;font-size:22px}
    .row{margin:12px 0;font-size:14px;color:#ddd}
    .label{color:#9B4FDE;font-weight:bold;display:block;font-size:11px;text-transform:uppercase}
    .badge{font-size:40px;margin-bottom:12px}`;
  if (!valid) {
    return `<html><head><style>${style}</style></head><body>
      <div class="card"><div class="badge">❌</div><h1>Certificat introuvable</h1>
      <p class="row">Aucun certificat valide ne correspond à cet identifiant.</p></div>
      </body></html>`;
  }
  const course = extra && extra.course;
  const student = extra && extra.student;
  return `<html><head><style>${style}</style></head><body>
    <div class="card">
      <div class="badge">✅</div>
      <h1>Certificat authentique</h1>
      <div class="row"><span class="label">Étudiant</span>${(student && student.nickname) || "—"}</div>
      <div class="row"><span class="label">Cours</span>${(course && course.title) || "—"}</div>
      <div class="row"><span class="label">Formateur</span>${(course && course.instructor_nickname) || "—"}</div>
      <div class="row"><span class="label">Terminé le</span>${new Date(enr.updated_at || enr.enrolled_at).toLocaleDateString()}</div>
      <div class="row" style="margin-top:20px;font-size:11px;color:#888">Vérifié via Lumino — écosystème Delta</div>
    </div>
    </body></html>`;
}

app.get("/", (req, res) => {
  res.send("Lumino auth verification service — OK");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Serveur démarré sur le port " + PORT));
