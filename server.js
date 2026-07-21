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

// ══════════════════════════════════════════════════════════
// SECRET JWT PAR APP
// ──────────────────────────────────────────────────────────
// Chaque projet Supabase a son PROPRE secret JWT legacy (Settings →
// API → JWT Settings). Un JWT signé avec le mauvais secret est
// censé être rejeté par ce projet-là (auth.jwt() renvoie vide côté
// RLS, ou 401 selon la configuration). Ce service étant partagé par
// plusieurs apps, il doit signer chaque JWT avec le secret DU BON
// projet — jamais un seul secret pour tous.
//
// Chaque app doit envoyer un champ "app" dans le corps de sa requête
// POST /verify-delta-auth (ex: {accCanisterId, dAppIdentToken, app:"wagnina"}).
// Ajoute une variable d'environnement JWT_SECRET_<NOM> sur Render pour
// chaque app, avec le secret JWT legacy exact de SON projet Supabase.
// ══════════════════════════════════════════════════════════
const APP_JWT_SECRETS = {
  lumino:      process.env.JWT_SECRET_LUMINO,
  wagnina:     process.env.JWT_SECRET_WAGNINA,
  deltarent:   process.env.JWT_SECRET_DELTARENT,
  deltawork:   process.env.JWT_SECRET_DELTAWORK,
  palacemarket:process.env.JWT_SECRET_PALACEMARKET,
};

function resolveJwtSecret(appName) {
  const key = (appName || "").toLowerCase().trim();
  const perAppSecret = APP_JWT_SECRETS[key];
  if (perAppSecret) return { secret: perAppSecret, source: `JWT_SECRET_${key.toUpperCase()}` };
  // Repli : ancien secret unique (JWT_SIGNING_SECRET), pour compatibilité
  // avec les apps qui n'envoient pas encore le champ "app". À corriger
  // app par app dès que possible — ce repli ne garantit PAS que le
  // secret corresponde au bon projet Supabase.
  if (process.env.JWT_SIGNING_SECRET) {
    return { secret: process.env.JWT_SIGNING_SECRET, source: "JWT_SIGNING_SECRET (repli générique — à corriger)" };
  }
  return { secret: null, source: null };
}

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
    const { accCanisterId, dAppIdentToken, app: appName } = req.body;
    if (!accCanisterId || !dAppIdentToken?.did || !dAppIdentToken?.token) {
      return res.status(400).json({ error: "Requête invalide" });
    }
    if (!appName) {
      console.warn("[verify-delta-auth] ⚠️ Champ 'app' absent de la requête — le client doit être mis à jour pour l'envoyer.");
    }

    console.log("[verify-delta-auth] Requête reçue — app:", appName || "(non fourni)", "accCanisterId:", accCanisterId, "did:", dAppIdentToken.did);

    const acctInfo = await verifyDeltaToken(accCanisterId, dAppIdentToken);
    console.log("[verify-delta-auth] Vérification canister réussie ✓", acctInfo);

    const { secret: jwtSecret, source: secretSource } = resolveJwtSecret(appName);
    if (!jwtSecret) {
      return res.status(500).json({ error: `Aucun secret JWT configuré pour l'app "${appName || '(non fourni)'}"` });
    }
    console.log("[verify-delta-auth] Secret JWT utilisé:", secretSource);

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

app.get("/", (req, res) => {
  const configured = Object.keys(APP_JWT_SECRETS).filter(k => !!APP_JWT_SECRETS[k]);
  res.send(
    "Lumino auth verification service — OK\n" +
    "Secrets JWT par app configurés: " + (configured.length ? configured.join(", ") : "(aucun)") + "\n" +
    "Repli générique JWT_SIGNING_SECRET: " + (process.env.JWT_SIGNING_SECRET ? "configuré" : "absent")
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Serveur démarré sur le port " + PORT));
                               
