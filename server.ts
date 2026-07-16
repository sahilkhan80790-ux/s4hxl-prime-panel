import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { createServer as createViteServer } from "vite";
import { 
  User, 
  SMMCategory, 
  SMMService, 
  SMMOrder, 
  SMMTransaction, 
  Ticket, 
  TicketMessage, 
  SMMProvider, 
  Coupon, 
  Announcement, 
  FAQ, 
  AuditLog,
  UserRole
} from "./src/types";

const PORT = 3000;
const DB_FILE = path.join(process.cwd(), "db.json");

// Helper: Secure token creation using native cryptography
const JWT_SECRET = process.env.JWT_SECRET || "s4hxl_prime_panel_ultra_secure_secret_key_2026";

function generateToken(user: User): string {
  const payload = JSON.stringify({ id: user.id, role: user.role, exp: Date.now() + 24 * 60 * 60 * 1000 * 7 }); // 7 days
  const signature = crypto.createHmac("sha256", JWT_SECRET).update(payload).digest("hex");
  return Buffer.from(payload).toString("base64") + "." + signature;
}

function verifyToken(token: string): { id: string; role: UserRole } | null {
  try {
    const [payloadB64, signature] = token.split(".");
    if (!payloadB64 || !signature) return null;
    const payloadStr = Buffer.from(payloadB64, "base64").toString();
    const payload = JSON.parse(payloadStr);
    
    // Verify signature
    const expectedSignature = crypto.createHmac("sha256", JWT_SECRET).update(payloadStr).digest("hex");
    if (signature !== expectedSignature) return null;
    
    // Check expiration
    if (payload.exp < Date.now()) return null;
    
    return payload;
  } catch {
    return null;
  }
}

function hashPassword(password: string): string {
  return crypto.createHmac("sha256", "s4hxl_salt_hash_2026").update(password).digest("hex");
}

// Database JSON State Schema
interface DBState {
  users: User[];
  categories: SMMCategory[];
  services: SMMService[];
  orders: SMMOrder[];
  transactions: SMMTransaction[];
  tickets: Ticket[];
  providers: SMMProvider[];
  coupons: Coupon[];
  announcements: Announcement[];
  faqs: FAQ[];
  auditLogs: AuditLog[];
}

// Default Data Seeds
const defaultCategories: SMMCategory[] = [
  { id: "cat-ig", name: "Instagram (HQ & Fast)", icon: "Instagram" },
  { id: "cat-yt", name: "YouTube (Monetization & Views)", icon: "Youtube" },
  { id: "cat-fb", name: "Facebook (Likes & Pages)", icon: "Facebook" },
  { id: "cat-tg", name: "Telegram (Members & Views)", icon: "Send" },
  { id: "cat-tw", name: "Twitter / X (Followers & Likes)", icon: "Twitter" },
  { id: "cat-dc", name: "Discord (Members & Invites)", icon: "Disc" },
  { id: "cat-tt", name: "TikTok (Followers & Views)", icon: "Video" },
  { id: "cat-sp", name: "Spotify & SoundCloud", icon: "Music" },
  { id: "cat-web", name: "Website Traffic & SEO Reviews", icon: "Globe" }
];

const defaultServices: SMMService[] = [
  {
    id: "serv-ig-fol-hq",
    categoryId: "cat-ig",
    name: "Instagram Followers [High Quality | Non-Drop | Real Profiles | 365 Days Refill]",
    ratePer1000: 1.25,
    minOrder: 10,
    maxOrder: 100000,
    description: "⚡ Speed: 10k-50k per day. Quality: High-quality organic looking profiles with posts. Refill: 365 Days Auto Refill. Instant start.",
    averageTime: "12 mins",
    isFavorite: true,
    rating: 4.9,
    refillEnabled: true
  },
  {
    id: "serv-ig-lik-inst",
    categoryId: "cat-ig",
    name: "Instagram Likes [Super Fast | Lifetime Guarantee | Instant Start]",
    ratePer1000: 0.38,
    minOrder: 20,
    maxOrder: 50000,
    description: "⚡ Speed: Instant start. Quality: Real profiles. High-speed delivery. Lifetime refill guarantee.",
    averageTime: "3 mins",
    isFavorite: false,
    rating: 4.8,
    refillEnabled: false
  },
  {
    id: "serv-ig-view-reels",
    categoryId: "cat-ig",
    name: "Instagram Reels Views + Reach [Viral Speed | Max 10M | Instant]",
    ratePer1000: 0.08,
    minOrder: 100,
    maxOrder: 10000000,
    description: "⚡ Speed: 1M/day. Boosts your Reels algorithm ranking. Instant start.",
    averageTime: "1 min",
    isFavorite: false,
    rating: 4.7,
    refillEnabled: false
  },
  {
    id: "serv-yt-sub-nd",
    categoryId: "cat-yt",
    name: "YouTube Subscribers [Non-Drop | Organic Speed | Monetization Safe | 30D Refill]",
    ratePer1000: 14.80,
    minOrder: 50,
    maxOrder: 20000,
    description: "⚡ Speed: 100-300 per day (safe organic velocity). Non-drop, monetization compliant.",
    averageTime: "1 hr 30 mins",
    isFavorite: true,
    rating: 5.0,
    refillEnabled: true
  },
  {
    id: "serv-yt-view-real",
    categoryId: "cat-yt",
    name: "YouTube High Retention Views [AdWords Safe | Average 4-7 Min Watch Time]",
    ratePer1000: 2.45,
    minOrder: 500,
    maxOrder: 1000000,
    description: "⚡ Speed: 10k-20k/day. Safe for monetized channels. Helps video SEO ranking.",
    averageTime: "24 mins",
    isFavorite: false,
    rating: 4.9,
    refillEnabled: true
  },
  {
    id: "serv-tg-mem-real",
    categoryId: "cat-tg",
    name: "Telegram Channel Members [Ultra High Quality | Active Accounts | 0% Drop]",
    ratePer1000: 0.95,
    minOrder: 100,
    maxOrder: 50000,
    description: "⚡ Speed: 20k/day. Real users with customized avatars and bios. No drop guarantee.",
    averageTime: "8 mins",
    isFavorite: true,
    rating: 4.9,
    refillEnabled: true
  },
  {
    id: "serv-dc-mem-on",
    categoryId: "cat-dc",
    name: "Discord Online Members [Always Online | Custom Avatar | Custom Nickname]",
    ratePer1000: 3.20,
    minOrder: 50,
    maxOrder: 10000,
    description: "⚡ Online discord members who stay logged in. Professional look. Helps look active.",
    averageTime: "15 mins",
    isFavorite: false,
    rating: 4.6,
    refillEnabled: false
  },
  {
    id: "serv-tw-fol-usa",
    categoryId: "cat-tw",
    name: "Twitter / X Followers [USA Targeted Profiles | HQ Bio & Tweets | 90D Refill]",
    ratePer1000: 4.90,
    minOrder: 100,
    maxOrder: 25000,
    description: "⚡ Speed: 2k/day. Premium high-quality USA profiles with regular posting histories and bios.",
    averageTime: "40 mins",
    isFavorite: false,
    rating: 4.8,
    refillEnabled: true
  },
  {
    id: "serv-tt-fol-inst",
    categoryId: "cat-tt",
    name: "TikTok Followers [Instant Delivery | Real Users | High Quality]",
    ratePer1000: 1.65,
    minOrder: 50,
    maxOrder: 100000,
    description: "⚡ Instant start. High completion speed. Real active TikTok accounts.",
    averageTime: "5 mins",
    isFavorite: true,
    rating: 4.9,
    refillEnabled: false
  },
  {
    id: "serv-web-traf-seo",
    categoryId: "cat-web",
    name: "Google SEO Organic Search Traffic [USA Target | Custom Keyword Searches]",
    ratePer1000: 0.75,
    minOrder: 1000,
    maxOrder: 1000000,
    description: "⚡ Organic traffic tracking on Google Analytics. Bounce rate: 10-15%. Session time: 2-3 mins.",
    averageTime: "2 mins",
    isFavorite: false,
    rating: 4.8,
    refillEnabled: false
  }
];

const defaultProviders: SMMProvider[] = [
  {
    id: "prov-peakerr",
    name: "Peakerr API Provider (Primary)",
    apiUrl: "https://api.peakerr.example.com/v2",
    apiKey: "pk_live_483a92fc0b382d9213efbd6e",
    balance: 1485.50,
    status: "active"
  },
  {
    id: "prov-perfect",
    name: "PerfectPanel Aggregator V2",
    apiUrl: "https://perfectpanel.example.net/api/v2",
    apiKey: "pp_api_99cde78ab2030d9cb7f1837e",
    balance: 500.00,
    status: "inactive"
  }
];

const defaultCoupons: Coupon[] = [
  { id: "coup-prime20", code: "PRIME20", type: "percentage", value: 20, usageLimit: 100, usedCount: 14, expiryDate: "2026-12-31", active: true },
  { id: "coup-flat5", code: "FLAT5USD", type: "flat", value: 5.0, usageLimit: 50, usedCount: 8, expiryDate: "2026-11-30", active: true }
];

const defaultAnnouncements: Announcement[] = [
  {
    id: "ann-1",
    title: "⚡ NEW SERVICES: TikTok Instant Views & Shares Added!",
    content: "We have updated our TikTok delivery algorithm! TikTok views now start in less than 30 seconds with prices starting as low as $0.05 per 1,000 views. Make sure to check them out under the TikTok category.",
    type: "success",
    date: "2026-07-15T12:00:00Z"
  },
  {
    id: "ann-2",
    title: "⚠️ Scheduled System Server Maintenance",
    content: "Our API provider sync will undergo a short upgrade on July 20th from 02:00 UTC to 02:15 UTC. Order queuing and delivery won't be disrupted, but the provider balance and API tester may be briefly offline.",
    type: "warning",
    date: "2026-07-14T10:00:00Z"
  },
  {
    id: "ann-3",
    title: "🎁 Special Deposit Bonus Active: 10% Extra on UPI Payments!",
    content: "For a limited time, get 10% extra balance automatically when depositing with UPI QR or Paytm transfers. The bonus is instantly added to your wallet.",
    type: "info",
    date: "2026-07-10T08:00:00Z"
  }
];

const defaultFaqs: FAQ[] = [
  {
    id: "faq-1",
    question: "What is S4HXL PRIME PANEL and how does it work?",
    answer: "S4HXL PRIME PANEL is a professional social media marketing (SMM) platform providing bulk social media services like followers, likes, views, subscribers, and comments. You register, recharge your secure wallet, choose a service, and input your campaign link to instantly grow your presence."
  },
  {
    id: "faq-2",
    question: "Are your services safe for my social media accounts?",
    answer: "Yes, 100%. We only deliver highly safe, algorithm-compliant promotional views and real-looking profiles. We never ask for your passwords, and all methods are fully natural and organic to safeguard against account restrictions."
  },
  {
    id: "faq-3",
    question: "What does 'Refill' mean on services?",
    answer: "A refill service means if some followers or likes drop over time, our system will automatically detect the drop (or you can trigger a manual refill click in your dashboard) and top up the count back to the ordered quantity completely free of charge."
  },
  {
    id: "faq-4",
    question: "How long does it take for my orders to start?",
    answer: "Most services start within 1 to 15 minutes. High-quality services and large subscribers orders have an 'average starting time' shown on the order page so you can plan your campaigns perfectly."
  }
];

// Read/Write DB helper functions
function loadDatabase(): DBState {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const initialDb: DBState = {
        users: [
          {
            id: "user-admin",
            username: "admin",
            email: "admin@s4hxl.com",
            role: "admin",
            balance: 5000.00,
            verified: true,
            twoFactorEnabled: false,
            referralBalance: 125.50,
            referralClicks: 152,
            referralConversions: 18,
            createdAt: new Date().toISOString()
          },
          {
            id: "user-reseller",
            username: "reseller_pro",
            email: "reseller@s4hxl.com",
            role: "reseller",
            balance: 1500.00,
            verified: true,
            twoFactorEnabled: true,
            twoFactorSecret: "GBSWY3DPEB3W64TBNQ======",
            referrerId: "user-admin",
            referralBalance: 45.00,
            referralClicks: 84,
            referralConversions: 7,
            createdAt: new Date().toISOString()
          },
          {
            id: "user-demo",
            username: "demouser",
            email: "user@s4hxl.com",
            role: "user",
            balance: 250.00,
            verified: true,
            twoFactorEnabled: false,
            referrerId: "user-reseller",
            referralBalance: 0.00,
            referralClicks: 12,
            referralConversions: 0,
            createdAt: new Date().toISOString()
          }
        ],
        categories: defaultCategories,
        services: defaultServices,
        orders: [
          {
            id: "ord-10001",
            userId: "user-demo",
            serviceId: "serv-ig-fol-hq",
            link: "https://instagram.com/s4hxl_prime",
            quantity: 2000,
            charge: 2.50,
            startCount: 412,
            remains: 0,
            status: "completed",
            date: "2026-07-14T15:24:00Z",
            type: "single"
          },
          {
            id: "ord-10002",
            userId: "user-demo",
            serviceId: "serv-yt-sub-nd",
            link: "https://youtube.com/c/s4hxl_tech",
            quantity: 500,
            charge: 7.40,
            startCount: 1530,
            remains: 120,
            status: "inprogress",
            date: "2026-07-15T08:12:00Z",
            type: "single"
          },
          {
            id: "ord-10003",
            userId: "user-demo",
            serviceId: "serv-tg-mem-real",
            link: "https://t.me/s4hxl_channels",
            quantity: 1000,
            charge: 0.95,
            startCount: 0,
            remains: 1000,
            status: "pending",
            date: "2026-07-16T01:30:00Z",
            type: "single"
          }
        ],
        transactions: [
          {
            id: "tx-20001",
            userId: "user-demo",
            amount: 150.00,
            paymentMethod: "UPI QR (PhonePe)",
            status: "completed",
            date: "2026-07-14T10:00:00Z",
            invoiceNo: "INV-928103-2026"
          },
          {
            id: "tx-20002",
            userId: "user-demo",
            amount: 100.00,
            paymentMethod: "Razorpay (Credit Card)",
            status: "completed",
            date: "2026-07-15T18:45:00Z",
            invoiceNo: "INV-928104-2026"
          }
        ],
        tickets: [
          {
            id: "tick-30001",
            userId: "user-demo",
            subject: "Order #ord-10002 YouTube subscribers speed boost request",
            priority: "high",
            category: "Order",
            status: "pending",
            lastUpdated: "2026-07-15T19:30:00Z",
            messages: [
              {
                id: "msg-1",
                senderId: "user-demo",
                senderName: "demouser",
                senderRole: "user",
                text: "Hello, could you please speed up the subscribers delivery for order #ord-10002? It started running but is going a bit slow. Thank you!",
                date: "2026-07-15T19:00:00Z"
              },
              {
                id: "msg-2",
                senderId: "user-admin",
                senderName: "Admin Sahil",
                senderRole: "admin",
                text: "Hello! YouTube Subscribers are delivered with organic speed safety limits (100-300/day) to prevent social media drop filters and protect your channel's monetization safety. Your order is running absolutely smoothly!",
                date: "2026-07-15T19:30:00Z"
              }
            ]
          }
        ],
        providers: defaultProviders,
        coupons: defaultCoupons,
        announcements: defaultAnnouncements,
        faqs: defaultFaqs,
        auditLogs: [
          {
            id: "log-1",
            userId: "user-demo",
            username: "demouser",
            action: "Account Login",
            ipAddress: "157.48.201.32",
            device: "Chrome (Windows 11)",
            date: "2026-07-16T02:00:00Z"
          }
        ]
      };
      
      // Hash pre-seeded user passwords securely
      initialDb.users[0].twoFactorSecret = hashPassword("admin123"); // we will piggyback password hashes in an internal db representation
      initialDb.users[1].twoFactorSecret = hashPassword("reseller123");
      initialDb.users[2].twoFactorSecret = hashPassword("user123");
      
      fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2));
      return initialDb;
    }
    return JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
  } catch (err) {
    console.error("Database loading error, returning mock schema:", err);
    return {
      users: [], categories: [], services: [], orders: [],
      transactions: [], tickets: [], providers: [], coupons: [],
      announcements: [], faqs: [], auditLogs: []
    };
  }
}

function saveDatabase(state: DBState) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(state, null, 2));
  } catch (err) {
    console.error("Database save failed:", err);
  }
}

// REST Backend Engine Initialize
const db = loadDatabase();

async function startServer() {
  const app = express();
  app.use(express.json());

  // CORS support
  app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    if (req.method === "OPTIONS") {
      return res.sendStatus(200);
    }
    next();
  });

  // Log audit activity helper
  const logAudit = (userId: string, username: string, action: string, req: express.Request) => {
    const ip = req.headers["x-forwarded-for"] as string || req.socket.remoteAddress || "127.0.0.1";
    const dev = req.headers["user-agent"] || "Unknown Device";
    const newLog: AuditLog = {
      id: "log-" + Date.now() + Math.floor(Math.random() * 100),
      userId,
      username,
      action,
      ipAddress: ip,
      device: dev,
      date: new Date().toISOString()
    };
    db.auditLogs.unshift(newLog);
    if (db.auditLogs.length > 500) db.auditLogs.pop(); // limit database log growth
    saveDatabase(db);
  };

  // Auth Middleware
  const authenticateUser = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized access. Token is missing." });
    }
    const token = authHeader.split(" ")[1];
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ error: "Session expired or invalid token. Please login again." });
    }
    
    const user = db.users.find(u => u.id === payload.id);
    if (!user) {
      return res.status(401).json({ error: "User account no longer exists." });
    }
    
    // Attach user to request
    (req as any).user = user;
    next();
  };

  // Admin and Role guards
  const requireRole = (roles: UserRole[]) => {
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
      const user = (req as any).user;
      if (!user || !roles.includes(user.role)) {
        return res.status(403).json({ error: "Access denied. Insufficient administrative privileges." });
      }
      next();
    };
  };

  // ==================== AUTH ENTITY APIs ====================

  app.post("/api/auth/signup", (req, res) => {
    const { username, email, password, referrerId } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: "Username, email and password are required." });
    }
    
    const existingEmail = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
    const existingName = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (existingEmail) return res.status(400).json({ error: "Email address is already registered." });
    if (existingName) return res.status(400).json({ error: "Username is already taken." });

    let finalReferrer: string | undefined = undefined;
    if (referrerId) {
      const refUser = db.users.find(u => u.id === referrerId || u.username === referrerId);
      if (refUser) {
        finalReferrer = refUser.id;
        refUser.referralClicks += 1;
        refUser.referralConversions += 1;
      }
    }

    const newUser: User = {
      id: "user-" + Date.now(),
      username: username.toLowerCase().replace(/\s+/g, ""),
      email: email.toLowerCase(),
      role: "user",
      balance: 0.00,
      verified: true,
      twoFactorEnabled: false,
      twoFactorSecret: hashPassword(password), // Store password hash here internally
      referrerId: finalReferrer,
      referralBalance: 0.00,
      referralClicks: 0,
      referralConversions: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    saveDatabase(db);

    const token = generateToken(newUser);
    logAudit(newUser.id, newUser.username, "Registered a new account", req);

    res.status(201).json({
      message: "Registration successful!",
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        balance: newUser.balance,
        verified: newUser.verified,
        twoFactorEnabled: newUser.twoFactorEnabled,
        referralClicks: newUser.referralClicks,
        referralConversions: newUser.referralConversions,
        referralBalance: newUser.referralBalance
      }
    });
  });

  app.post("/api/auth/login", (req, res) => {
    const { emailOrUsername, password, twoFactorCode } = req.body;
    if (!emailOrUsername || !password) {
      return res.status(400).json({ error: "Please enter your username/email and password." });
    }

    const hash = hashPassword(password);
    const user = db.users.find(u => 
      (u.email.toLowerCase() === emailOrUsername.toLowerCase() || 
       u.username.toLowerCase() === emailOrUsername.toLowerCase()) && 
      u.twoFactorSecret === hash
    );

    if (!user) {
      return res.status(401).json({ error: "Invalid login credentials. Please check your spelling and try again." });
    }

    if (user.twoFactorEnabled && !twoFactorCode) {
      return res.json({ require2FA: true, userId: user.id });
    }

    if (user.twoFactorEnabled && twoFactorCode !== "123456") { // Default simulation code
      return res.status(400).json({ error: "Invalid Two-Factor Authentication OTP code." });
    }

    const token = generateToken(user);
    
    // Track location simulation
    user.ipAddress = req.headers["x-forwarded-for"] as string || req.socket.remoteAddress || "127.0.0.1";
    user.lastLogin = new Date().toISOString();
    user.device = req.headers["user-agent"] || "Chrome browser";
    saveDatabase(db);

    logAudit(user.id, user.username, "Logged in to panel", req);

    res.json({
      message: "Welcome back!",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance,
        verified: user.verified,
        twoFactorEnabled: user.twoFactorEnabled,
        referralClicks: user.referralClicks,
        referralConversions: user.referralConversions,
        referralBalance: user.referralBalance
      }
    });
  });

  app.get("/api/auth/me", authenticateUser, (req, res) => {
    const user = (req as any).user;
    res.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance,
        verified: user.verified,
        twoFactorEnabled: user.twoFactorEnabled,
        referrerId: user.referrerId,
        referralBalance: user.referralBalance,
        referralClicks: user.referralClicks,
        referralConversions: user.referralConversions,
        createdAt: user.createdAt,
        ipAddress: user.ipAddress,
        lastLogin: user.lastLogin,
        device: user.device
      }
    });
  });

  app.post("/api/auth/twofactor", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    const { enable } = req.body;
    user.twoFactorEnabled = !!enable;
    saveDatabase(db);
    logAudit(user.id, user.username, `${enable ? 'Enabled' : 'Disabled'} 2FA Security`, req);
    res.json({ success: true, twoFactorEnabled: user.twoFactorEnabled, secret: "GBSWY3DPEB3W64TBNQ======" });
  });

  // ==================== SMM SERVICES & CATEGORIES APIs ====================

  app.get("/api/services", (req, res) => {
    res.json({
      categories: db.categories,
      services: db.services
    });
  });

  // Admin manage categories
  app.post("/api/admin/categories", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    const { name, icon } = req.body;
    if (!name) return res.status(400).json({ error: "Category name is required." });
    
    const newCategory: SMMCategory = {
      id: "cat-" + Date.now(),
      name,
      icon: icon || "Layers"
    };

    db.categories.push(newCategory);
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Created service category: ${name}`, req);
    res.status(201).json(newCategory);
  });

  app.put("/api/admin/categories/:id", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    const { name, icon } = req.body;
    const cat = db.categories.find(c => c.id === req.params.id);
    if (!cat) return res.status(404).json({ error: "Category not found." });

    if (name) cat.name = name;
    if (icon) cat.icon = icon;
    
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Updated category: ${cat.name}`, req);
    res.json(cat);
  });

  app.delete("/api/admin/categories/:id", authenticateUser, requireRole(["admin"]), (req, res) => {
    const index = db.categories.findIndex(c => c.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: "Category not found." });
    
    const catName = db.categories[index].name;
    db.categories.splice(index, 1);
    
    // Cascade delete services in category
    db.services = db.services.filter(s => s.categoryId !== req.params.id);

    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Deleted category: ${catName}`, req);
    res.json({ success: true, message: "Category and associated SMM services deleted." });
  });

  // Admin manage services
  app.post("/api/admin/services", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    const { categoryId, name, ratePer1000, minOrder, maxOrder, description, averageTime, refillEnabled } = req.body;
    if (!categoryId || !name || !ratePer1000 || !minOrder || !maxOrder) {
      return res.status(400).json({ error: "Required fields are missing." });
    }

    const newService: SMMService = {
      id: "serv-" + Date.now(),
      categoryId,
      name,
      ratePer1000: Number(ratePer1000),
      minOrder: Number(minOrder),
      maxOrder: Number(maxOrder),
      description: description || "",
      averageTime: averageTime || "Instant",
      rating: 5.0,
      refillEnabled: !!refillEnabled
    };

    db.services.push(newService);
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Created SMM service: ${name}`, req);
    res.status(201).json(newService);
  });

  app.put("/api/admin/services/:id", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    const s = db.services.find(serv => serv.id === req.params.id);
    if (!s) return res.status(404).json({ error: "Service not found." });

    const { categoryId, name, ratePer1000, minOrder, maxOrder, description, averageTime, refillEnabled } = req.body;
    
    if (categoryId) s.categoryId = categoryId;
    if (name) s.name = name;
    if (ratePer1000 !== undefined) s.ratePer1000 = Number(ratePer1000);
    if (minOrder !== undefined) s.minOrder = Number(minOrder);
    if (maxOrder !== undefined) s.maxOrder = Number(maxOrder);
    if (description !== undefined) s.description = description;
    if (averageTime !== undefined) s.averageTime = averageTime;
    if (refillEnabled !== undefined) s.refillEnabled = !!refillEnabled;

    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Edited SMM service: ${s.name}`, req);
    res.json(s);
  });

  app.delete("/api/admin/services/:id", authenticateUser, requireRole(["admin"]), (req, res) => {
    const index = db.services.findIndex(serv => serv.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: "Service not found." });
    
    const name = db.services[index].name;
    db.services.splice(index, 1);
    
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Deleted SMM service: ${name}`, req);
    res.json({ success: true, message: "SMM service deleted." });
  });

  // Favorite toggle (user action)
  app.post("/api/services/:id/favorite", authenticateUser, (req, res) => {
    const serv = db.services.find(s => s.id === req.params.id);
    if (!serv) return res.status(404).json({ error: "Service not found." });
    
    serv.isFavorite = !serv.isFavorite;
    saveDatabase(db);
    res.json({ success: true, isFavorite: serv.isFavorite });
  });

  // ==================== SMM ORDERS ENGINE APIs ====================

  app.get("/api/orders", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    let userOrders = db.orders;
    if (user.role !== "admin" && user.role !== "subadmin") {
      userOrders = db.orders.filter(o => o.userId === user.id);
    }
    
    // Attach details
    const formatted = userOrders.map(o => {
      const service = db.services.find(s => s.id === o.serviceId);
      const owner = db.users.find(u => u.id === o.userId);
      return {
        ...o,
        serviceName: service ? service.name : "Legacy SMM Service",
        username: owner ? owner.username : "Deleted User"
      };
    });

    res.json({ orders: formatted });
  });

  // Place SMM Order
  app.post("/api/orders", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    const { serviceId, link, quantity, couponCode } = req.body;

    if (!serviceId || !link || !quantity) {
      return res.status(400).json({ error: "Please choose a service, provide a target link, and quantity." });
    }

    const service = db.services.find(s => s.id === serviceId);
    if (!service) return res.status(404).json({ error: "The chosen SMM service is currently unavailable." });

    const qty = Number(quantity);
    if (qty < service.minOrder || qty > service.maxOrder) {
      return res.status(400).json({ 
        error: `Invalid Quantity! Order size must be between ${service.minOrder.toLocaleString()} and ${service.maxOrder.toLocaleString()} units.` 
      });
    }

    // Calculate base charge
    let baseCharge = (service.ratePer1000 * qty) / 1000;
    
    // Apply discount coupons
    let couponDiscount = 0;
    if (couponCode) {
      const coupon = db.coupons.find(c => c.code.toUpperCase() === couponCode.toUpperCase() && c.active);
      if (coupon) {
        if (new Date(coupon.expiryDate) < new Date()) {
          return res.status(400).json({ error: "The promotional coupon has expired." });
        }
        if (coupon.usedCount >= coupon.usageLimit) {
          return res.status(400).json({ error: "The promotional coupon code has reached its maximum usage limit." });
        }
        if (coupon.type === "percentage") {
          couponDiscount = (baseCharge * coupon.value) / 100;
        } else {
          couponDiscount = Math.min(baseCharge, coupon.value);
        }
        coupon.usedCount += 1;
      } else {
        return res.status(400).json({ error: "Invalid promotional coupon code." });
      }
    }

    // Apply reseller discount if role matches
    let discountMultiplier = 1.0;
    if (user.role === "reseller") {
      discountMultiplier = 0.90; // Resellers enjoy a automatic 10% premium pricing discount
    }
    
    const finalCharge = Number(((baseCharge - couponDiscount) * discountMultiplier).toFixed(4));

    if (user.balance < finalCharge) {
      return res.status(400).json({ 
        error: `Insufficient balance! Your current wallet balance is $${user.balance.toFixed(2)}, but this order requires $${finalCharge.toFixed(2)}.` 
      });
    }

    // Deduct user wallet
    user.balance = Number((user.balance - finalCharge).toFixed(4));

    const newOrder: SMMOrder = {
      id: "ord-" + (10000 + db.orders.length + 1),
      userId: user.id,
      serviceId,
      link,
      quantity: qty,
      charge: finalCharge,
      startCount: Math.floor(Math.random() * 5000), // simulate dynamic SMM environment start point
      remains: qty,
      status: "pending",
      date: new Date().toISOString(),
      type: "single"
    };

    db.orders.push(newOrder);

    // Apply Affiliate referral commission (e.g. 5% referral earning for affiliates on every order)
    if (user.referrerId) {
      const referrer = db.users.find(u => u.id === user.referrerId);
      if (referrer) {
        const commAmount = Number((finalCharge * 0.05).toFixed(4));
        referrer.referralBalance = Number((referrer.referralBalance + commAmount).toFixed(4));
        referrer.balance = Number((referrer.balance + commAmount).toFixed(4));
        
        // Log transaction for referral
        const referralTx: SMMTransaction = {
          id: "tx-" + Date.now() + "-ref",
          userId: referrer.id,
          amount: commAmount,
          paymentMethod: "Referral Commission",
          status: "completed",
          date: new Date().toISOString(),
          invoiceNo: "REF-" + Math.floor(100000 + Math.random() * 900000),
          notes: `Affiliate earning 5% commission from direct referral: ${user.username}`
        };
        db.transactions.unshift(referralTx);
      }
    }

    saveDatabase(db);
    logAudit(user.id, user.username, `Placed new SMM order #${newOrder.id} (${qty} units for $${finalCharge})`, req);

    res.status(201).json({
      message: "Order placed successfully!",
      order: newOrder,
      userBalance: user.balance
    });
  });

  // Bulk and Mass SMM Order placing
  app.post("/api/orders/bulk", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    const { ordersList } = req.body; // array of { serviceId, link, quantity }
    
    if (!ordersList || !Array.isArray(ordersList) || ordersList.length === 0) {
      return res.status(400).json({ error: "Please input a valid orders list." });
    }

    let totalCost = 0;
    const resolved: SMMOrder[] = [];
    
    for (const item of ordersList) {
      const service = db.services.find(s => s.id === item.serviceId);
      if (!service) continue;
      const qty = Number(item.quantity);
      if (qty < service.minOrder || qty > service.maxOrder) continue;
      
      const charge = Number(((service.ratePer1000 * qty) / 1000 * (user.role === "reseller" ? 0.90 : 1.0)).toFixed(4));
      totalCost += charge;
      resolved.push({
        id: "", // filled below
        userId: user.id,
        serviceId: service.id,
        link: item.link,
        quantity: qty,
        charge,
        startCount: 0,
        remains: qty,
        status: "pending",
        date: new Date().toISOString(),
        type: "bulk"
      });
    }

    if (resolved.length === 0) {
      return res.status(400).json({ error: "None of the bulk orders fulfilled SMM safety criteria or range bounds." });
    }

    if (user.balance < totalCost) {
      return res.status(400).json({ error: `Insufficient wallet balance to place bulk orders. Required: $${totalCost.toFixed(2)}.` });
    }

    user.balance = Number((user.balance - totalCost).toFixed(4));

    resolved.forEach((newOrd, idx) => {
      newOrd.id = "ord-" + (10000 + db.orders.length + idx + 1);
      db.orders.push(newOrd);
    });

    saveDatabase(db);
    logAudit(user.id, user.username, `Placed bulk orders of size ${resolved.length}`, req);
    res.status(201).json({ message: "Bulk SMM orders processed successfully!", balance: user.balance });
  });

  // Mass Order processing (Paste multi lines of link|quantity|serviceId)
  app.post("/api/orders/mass", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    const { rawText, serviceId } = req.body; // lines: link|quantity
    if (!rawText || !serviceId) {
      return res.status(400).json({ error: "Raw input and target service are required." });
    }

    const service = db.services.find(s => s.id === serviceId);
    if (!service) return res.status(404).json({ error: "Target SMM service not active." });

    const lines = rawText.split("\n");
    let totalCost = 0;
    const validOrders: SMMOrder[] = [];

    lines.forEach((line: string) => {
      const parts = line.split("|");
      if (parts.length >= 2) {
        const link = parts[0].trim();
        const qty = Number(parts[1].trim());
        if (link && !isNaN(qty) && qty >= service.minOrder && qty <= service.maxOrder) {
          const charge = Number(((service.ratePer1000 * qty) / 1000 * (user.role === "reseller" ? 0.90 : 1.0)).toFixed(4));
          totalCost += charge;
          validOrders.push({
            id: "",
            userId: user.id,
            serviceId: service.id,
            link,
            quantity: qty,
            charge,
            startCount: 0,
            remains: qty,
            status: "pending",
            date: new Date().toISOString(),
            type: "mass"
          });
        }
      }
    });

    if (validOrders.length === 0) {
      return res.status(400).json({ error: "No valid orders parsed. Formats must strictly match: link|quantity" });
    }

    if (user.balance < totalCost) {
      return res.status(400).json({ error: `Insufficient wallet balance. Total mass cost: $${totalCost.toFixed(2)}.` });
    }

    user.balance = Number((user.balance - totalCost).toFixed(4));

    validOrders.forEach((newOrd, idx) => {
      newOrd.id = "ord-" + (10000 + db.orders.length + idx + 1);
      db.orders.push(newOrd);
    });

    saveDatabase(db);
    logAudit(user.id, user.username, `Placed mass orders of size ${validOrders.length}`, req);
    res.json({ message: "Mass orders queued!", balance: user.balance });
  });

  // User refill or cancellation trigger
  app.post("/api/orders/:id/refill", authenticateUser, (req, res) => {
    const order = db.orders.find(o => o.id === req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found." });
    
    // Simulate refill action
    logAudit((req as any).user.id, (req as any).user.username, `Triggered SMM service refill on #${order.id}`, req);
    res.json({ success: true, message: "Refill request successfully sent to API provider queue!" });
  });

  app.post("/api/orders/:id/cancel", authenticateUser, (req, res) => {
    const order = db.orders.find(o => o.id === req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found." });
    
    const user = db.users.find(u => u.id === order.userId);
    if (order.status !== "pending") {
      return res.status(400).json({ error: "Only pending SMM orders can be canceled." });
    }

    order.status = "canceled";
    
    // Refund user
    if (user) {
      user.balance = Number((user.balance + order.charge).toFixed(4));
      
      // Log transactional refund record
      const refundTx: SMMTransaction = {
        id: "tx-" + Date.now() + "-refund",
        userId: user.id,
        amount: order.charge,
        paymentMethod: "System Wallet Refund",
        status: "completed",
        date: new Date().toISOString(),
        invoiceNo: "REF-" + Math.floor(100000 + Math.random() * 900000),
        notes: `Auto refund due to manual cancellation of SMM Order #${order.id}`
      };
      db.transactions.unshift(refundTx);
    }

    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Canceled order #${order.id} and refunded $${order.charge}`, req);
    res.json({ success: true, message: "Order canceled and balance refunded.", order });
  });

  // Admin order operations
  app.put("/api/admin/orders/:id/status", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    const order = db.orders.find(o => o.id === req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found." });

    const { status, remains, startCount } = req.body;
    
    if (status) {
      // If updating to partial or canceled, handle dynamic refund offsets
      if ((status === "canceled" || status === "partial") && order.status !== "canceled" && order.status !== "partial") {
        const user = db.users.find(u => u.id === order.userId);
        if (user) {
          let refundCharge = order.charge;
          if (status === "partial") {
            const fraction = Number(remains || 0) / order.quantity;
            refundCharge = Number((order.charge * fraction).toFixed(4));
          }
          user.balance = Number((user.balance + refundCharge).toFixed(4));
          
          const refundTx: SMMTransaction = {
            id: "tx-" + Date.now() + "-adminref",
            userId: user.id,
            amount: refundCharge,
            paymentMethod: "System Wallet Refund",
            status: "completed",
            date: new Date().toISOString(),
            invoiceNo: "REF-" + Math.floor(100000 + Math.random() * 900000),
            notes: `Admin status adjustment (${status}) refund on Order #${order.id}`
          };
          db.transactions.unshift(refundTx);
        }
      }
      order.status = status;
    }
    if (remains !== undefined) order.remains = Number(remains);
    if (startCount !== undefined) order.startCount = Number(startCount);

    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Admin updated SMM Order #${order.id} status to ${status}`, req);
    res.json(order);
  });

  // ==================== WALLET & TRANSACTIONS APIs ====================

  app.get("/api/transactions", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    let userTx = db.transactions;
    if (user.role !== "admin" && user.role !== "subadmin") {
      userTx = db.transactions.filter(t => t.userId === user.id);
    }
    
    // Attach username details for easy reference
    const formatted = userTx.map(t => {
      const owner = db.users.find(u => u.id === t.userId);
      return {
        ...t,
        username: owner ? owner.username : "Deleted User"
      };
    });

    res.json({ transactions: formatted });
  });

  // Recharge initiation (Generates a dynamic Invoice & simulates automatic gateway verification)
  app.post("/api/wallet/recharge", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    const { amount, method, bonusApplied } = req.body;

    if (!amount || isNaN(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ error: "Please enter a valid deposit amount." });
    }

    const depAmount = Number(amount);
    const invoiceNo = "INV-" + Math.floor(100000 + Math.random() * 900000) + "-" + new Date().getFullYear();
    
    // Calculate 10% UPI bonus if applicable
    let bonusAmount = 0;
    if (bonusApplied && (method.includes("UPI") || method.includes("Paytm"))) {
      bonusAmount = Number((depAmount * 0.10).toFixed(4));
    }

    const totalToCredit = depAmount + bonusAmount;

    // Simulate instant success payment confirmation for user convenience in the sandbox UI,
    // and write actual Transaction histories to the server DB!
    user.balance = Number((user.balance + totalToCredit).toFixed(4));
    
    const newTx: SMMTransaction = {
      id: "tx-" + Date.now(),
      userId: user.id,
      amount: depAmount,
      paymentMethod: method || "Bank Transfer",
      status: "completed",
      date: new Date().toISOString(),
      invoiceNo,
      notes: `Deposited $${depAmount.toFixed(2)}${bonusAmount > 0 ? ` + 10% Extra Promotion Credit of $${bonusAmount.toFixed(2)}` : ""} via S4HXL automatic payment gateway.`
    };

    db.transactions.unshift(newTx);
    saveDatabase(db);
    logAudit(user.id, user.username, `Recharged wallet with $${depAmount.toFixed(2)} using ${method}`, req);

    res.status(201).json({
      message: "Deposit processed and verified successfully!",
      transaction: newTx,
      balance: user.balance
    });
  });

  // Admin manually deduct or add wallet balance
  app.post("/api/admin/users/:id/balance", authenticateUser, requireRole(["admin"]), (req, res) => {
    const target = db.users.find(u => u.id === req.params.id);
    if (!target) return res.status(404).json({ error: "User profile not found." });

    const { amount, action, reason } = req.body;
    if (!amount || isNaN(Number(amount))) return res.status(400).json({ error: "Invalid amount." });

    const val = Math.abs(Number(amount));
    if (action === "deduct") {
      if (target.balance < val) {
        return res.status(400).json({ error: "User balance is lower than deduction amount." });
      }
      target.balance = Number((target.balance - val).toFixed(4));
    } else {
      target.balance = Number((target.balance + val).toFixed(4));
    }

    const balanceTx: SMMTransaction = {
      id: "tx-" + Date.now(),
      userId: target.id,
      amount: val,
      paymentMethod: action === "deduct" ? "Wallet Adjustment (Deduction)" : "Wallet Adjustment (Credit)",
      status: "completed",
      date: new Date().toISOString(),
      invoiceNo: "ADJ-" + Math.floor(100000 + Math.random() * 900000),
      notes: reason || "Manual balancing adjustment by admin."
    };

    db.transactions.unshift(balanceTx);
    saveDatabase(db);
    
    logAudit((req as any).user.id, (req as any).user.username, `Admin manually adjusted balance of ${target.username} (${action} $${val})`, req);
    res.json({ success: true, balance: target.balance, message: "User wallet balance updated." });
  });

  // ==================== TICKET SYSTEM APIs ====================

  app.get("/api/tickets", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    let tix = db.tickets;
    if (user.role !== "admin" && user.role !== "subadmin") {
      tix = db.tickets.filter(t => t.userId === user.id);
    }

    const formatted = tix.map(t => {
      const owner = db.users.find(u => u.id === t.userId);
      return {
        ...t,
        username: owner ? owner.username : "Deleted User"
      };
    });

    res.json({ tickets: formatted });
  });

  app.get("/api/tickets/:id", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    const ticket = db.tickets.find(t => t.id === req.params.id);
    if (!ticket) return res.status(404).json({ error: "Ticket not found." });

    if (user.role !== "admin" && user.role !== "subadmin" && ticket.userId !== user.id) {
      return res.status(403).json({ error: "Access denied. You do not own this support ticket." });
    }

    const owner = db.users.find(u => u.id === ticket.userId);
    res.json({ 
      ticket: {
        ...ticket,
        username: owner ? owner.username : "Deleted User"
      }
    });
  });

  // Create Support Ticket
  app.post("/api/tickets", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    const { subject, priority, category, message } = req.body;

    if (!subject || !message) {
      return res.status(400).json({ error: "Subject and Message details are required." });
    }

    const newTicket: Ticket = {
      id: "tick-" + (30000 + db.tickets.length + 1),
      userId: user.id,
      subject,
      priority: priority || "medium",
      category: category || "Other",
      status: "open",
      lastUpdated: new Date().toISOString(),
      messages: [
        {
          id: "msg-" + Date.now(),
          senderId: user.id,
          senderName: user.username,
          senderRole: user.role,
          text: message,
          date: new Date().toISOString()
        }
      ]
    };

    db.tickets.unshift(newTicket);
    saveDatabase(db);
    logAudit(user.id, user.username, `Opened support ticket #${newTicket.id}`, req);

    res.status(201).json({
      message: "Support ticket opened successfully!",
      ticket: newTicket
    });
  });

  // Add Ticket Reply
  app.post("/api/tickets/:id/reply", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: "Please write a message response." });

    const ticket = db.tickets.find(t => t.id === req.params.id);
    if (!ticket) return res.status(404).json({ error: "Ticket not found." });

    if (user.role !== "admin" && user.role !== "subadmin" && ticket.userId !== user.id) {
      return res.status(403).json({ error: "Access denied. Ticket reply unauthorized." });
    }

    const newReply: TicketMessage = {
      id: "msg-" + Date.now() + Math.floor(Math.random() * 10),
      senderId: user.id,
      senderName: user.username,
      senderRole: user.role,
      text,
      date: new Date().toISOString()
    };

    ticket.messages.push(newReply);
    ticket.lastUpdated = new Date().toISOString();
    
    // Automatically change status
    if (user.role === "admin" || user.role === "subadmin") {
      ticket.status = "pending"; // Admin waiting for user reaction
    } else {
      ticket.status = "open"; // User replied, admin attention requested
    }

    saveDatabase(db);
    logAudit(user.id, user.username, `Replied to ticket #${ticket.id}`, req);
    res.json({ success: true, reply: newReply, ticket });
  });

  // Admin close support ticket
  app.post("/api/admin/tickets/:id/close", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    const ticket = db.tickets.find(t => t.id === req.params.id);
    if (!ticket) return res.status(404).json({ error: "Ticket not found." });

    ticket.status = "closed";
    ticket.lastUpdated = new Date().toISOString();
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Closed support ticket #${ticket.id}`, req);
    res.json({ success: true, ticket });
  });

  // ==================== AFFILIATE & REFERRALS APIs ====================

  app.get("/api/affiliates/stats", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    
    // Count direct referrals
    const referrals = db.users.filter(u => u.referrerId === user.id);
    
    res.json({
      clicks: user.referralClicks,
      conversions: referrals.length,
      commissionRate: "5%",
      referralBalance: user.referralBalance,
      referralsList: referrals.map(r => ({
        username: r.username,
        dateJoined: r.createdAt,
        verified: r.verified
      }))
    });
  });

  // Withdraw Referral balance to account balance
  app.post("/api/affiliates/withdraw", authenticateUser, (req, res) => {
    const user = (req as any).user as User;
    if (user.referralBalance <= 0) {
      return res.status(400).json({ error: "You do not have any referral commission earnings to withdraw." });
    }

    const amt = user.referralBalance;
    user.referralBalance = 0.00;
    user.balance = Number((user.balance + amt).toFixed(4));

    const withdrawTx: SMMTransaction = {
      id: "tx-" + Date.now() + "-aff",
      userId: user.id,
      amount: amt,
      paymentMethod: "Affiliate Commission Withdrawal",
      status: "completed",
      date: new Date().toISOString(),
      invoiceNo: "AFF-" + Math.floor(100000 + Math.random() * 900000),
      notes: `Withdrew $${amt.toFixed(2)} referral earnings into principal wallet balance.`
    };

    db.transactions.unshift(withdrawTx);
    saveDatabase(db);
    logAudit(user.id, user.username, `Withdrew affiliate commissions: $${amt.toFixed(2)}`, req);

    res.json({ message: "Commissions successfully transferred to main wallet balance!", balance: user.balance });
  });

  // Simulate a click on referral link (e.g. /register?ref=username)
  app.post("/api/affiliates/click", (req, res) => {
    const { refCode } = req.body;
    if (!refCode) return res.status(400).json({ error: "Referral code missing." });

    const refUser = db.users.find(u => u.username.toLowerCase() === refCode.toLowerCase() || u.id === refCode);
    if (refUser) {
      refUser.referralClicks += 1;
      saveDatabase(db);
      return res.json({ success: true, referrerId: refUser.id });
    }
    res.status(404).json({ error: "Referrer profile not found." });
  });

  // ==================== PROVIDER SYNC & API TESTER APIs ====================

  app.get("/api/providers", authenticateUser, requireRole(["admin"]), (req, res) => {
    res.json({ providers: db.providers });
  });

  // Simulate Fetch Provider Balance
  app.post("/api/admin/providers/:id/fetch-balance", authenticateUser, requireRole(["admin"]), (req, res) => {
    const provider = db.providers.find(p => p.id === req.params.id);
    if (!provider) return res.status(404).json({ error: "Provider not found." });

    // Simulate an external API call that successfully syncs the balance
    provider.balance = Number((1000 + Math.random() * 2000).toFixed(2));
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Synced balance for API provider: ${provider.name}`, req);
    res.json({ success: true, balance: provider.balance });
  });

  // Provider service mapping emulator (sync services)
  app.post("/api/admin/providers/:id/sync", authenticateUser, requireRole(["admin"]), (req, res) => {
    const provider = db.providers.find(p => p.id === req.params.id);
    if (!provider) return res.status(404).json({ error: "Provider not found." });

    // Simulate syncing new services from API provider and placing them into S4HXL DB
    const syncCount = 4;
    const newServices: SMMService[] = [
      {
        id: "serv-prov-ig-1",
        categoryId: "cat-ig",
        name: `Instagram Followers [PEAKERR SOURCE-${Math.floor(100 + Math.random() * 900)}]`,
        ratePer1000: 0.85,
        minOrder: 50,
        maxOrder: 250000,
        description: "⚡ Synced directly from Peakerr API. High retention automated delivery.",
        averageTime: "8 mins",
        rating: 4.8
      },
      {
        id: "serv-prov-yt-2",
        categoryId: "cat-yt",
        name: `YouTube Custom Comments [PEAKERR SOURCE-${Math.floor(100 + Math.random() * 900)}]`,
        ratePer1000: 18.50,
        minOrder: 10,
        maxOrder: 1000,
        description: "⚡ Real active YouTube viewer feedback. Synced from API.",
        averageTime: "4 mins",
        rating: 4.9
      }
    ];

    newServices.forEach(ns => {
      if (!db.services.find(s => s.id === ns.id)) {
        db.services.push(ns);
      }
    });

    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Automated sync services from SMM API provider: ${provider.name}`, req);
    res.json({ success: true, syncedCount: syncCount, services: newServices });
  });

  // Test SMM custom Provider API parameters
  app.post("/api/admin/providers/test", authenticateUser, requireRole(["admin"]), (req, res) => {
    const { apiUrl, apiKey, action } = req.body;
    if (!apiUrl || !apiKey) {
      return res.status(400).json({ error: "SMM Provider API Url and Secret API Key are required." });
    }

    // Simulate a successful verification output log
    const testLogs = [
      `[INFO] Initiating connection handshake to: ${apiUrl}`,
      `[INFO] Authorizing with supplied secret key: ${apiKey.substring(0, 5)}******`,
      `[SUCCESS] Connection authorized successfully! HTTP 200 OK`,
      `[RESULT] Connected SMM Endpoint model version: PP-SMM-API-V2`,
      `[RESULT] Account balance resolved: $1,485.50 USD`,
      `[RESULT] 247 SMM active services mapped.`
    ];

    res.json({
      success: true,
      logs: testLogs,
      message: "SMM Provider API connection test PASSED."
    });
  });

  // ==================== GENERAL INFO & FAQ APIs ====================

  app.get("/api/announcements", (req, res) => {
    res.json({ announcements: db.announcements });
  });

  app.get("/api/faqs", (req, res) => {
    res.json({ faqs: db.faqs });
  });

  // Admin coupon CRUD
  app.get("/api/admin/coupons", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    res.json({ coupons: db.coupons });
  });

  app.post("/api/admin/coupons", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    const { code, type, value, usageLimit, expiryDate } = req.body;
    if (!code || !type || !value || !usageLimit || !expiryDate) {
      return res.status(400).json({ error: "Coupon parameters are incomplete." });
    }

    const newCoupon: Coupon = {
      id: "coup-" + Date.now(),
      code: code.toUpperCase(),
      type,
      value: Number(value),
      usageLimit: Number(usageLimit),
      usedCount: 0,
      expiryDate,
      active: true
    };

    db.coupons.push(newCoupon);
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Created coupon code: ${newCoupon.code}`, req);
    res.status(201).json(newCoupon);
  });

  app.delete("/api/admin/coupons/:id", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    const index = db.coupons.findIndex(c => c.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: "Coupon not found." });
    
    const code = db.coupons[index].code;
    db.coupons.splice(index, 1);
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Deleted coupon code: ${code}`, req);
    res.json({ success: true });
  });

  // Admin user CRUD
  app.get("/api/admin/users", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    res.json({ users: db.users.map(u => ({ ...u, passwordHash: "HIDDEN" })) });
  });

  app.put("/api/admin/users/:id/role", authenticateUser, requireRole(["admin"]), (req, res) => {
    const { role } = req.body;
    const target = db.users.find(u => u.id === req.params.id);
    if (!target) return res.status(404).json({ error: "User not found." });

    target.role = role as UserRole;
    saveDatabase(db);
    logAudit((req as any).user.id, (req as any).user.username, `Updated user ${target.username} role to ${role}`, req);
    res.json(target);
  });

  // System audit logs
  app.get("/api/admin/audit-logs", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    res.json({ logs: db.auditLogs });
  });

  // ==================== SYSTEM ANALYTICS API ====================

  app.get("/api/admin/analytics", authenticateUser, requireRole(["admin", "subadmin"]), (req, res) => {
    // Orders today
    const startOfToday = new Date();
    startOfToday.setHours(0,0,0,0);
    const todayOrders = db.orders.filter(o => new Date(o.date) >= startOfToday);
    
    // Revenue calculations
    const totalRevenue = db.transactions
      .filter(t => t.status === "completed" && !t.paymentMethod.includes("Adjustment") && !t.paymentMethod.includes("Referral"))
      .reduce((sum, t) => sum + t.amount, 0);

    const pending = db.orders.filter(o => o.status === "pending").length;
    const inprogress = db.orders.filter(o => o.status === "inprogress").length;
    const completed = db.orders.filter(o => o.status === "completed").length;
    const canceled = db.orders.filter(o => o.status === "canceled").length;

    res.json({
      ordersToday: todayOrders.length,
      revenueToday: todayOrders.reduce((sum, o) => sum + o.charge, 0),
      totalRevenue,
      walletCirculation: db.users.reduce((sum, u) => sum + u.balance, 0),
      orderStats: { pending, inprogress, completed, canceled },
      totalUsers: db.users.length,
      totalTickets: db.tickets.length,
      totalServices: db.services.length
    });
  });


  // ==================== VITE CLIENT INTEGRATION MIDDLEWARE ====================

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`\n======================================================`);
    console.log(`🚀 S4HXL PRIME PANEL custom server initialized!`);
    console.log(`🌐 Application running live on: http://localhost:${PORT}`);
    console.log(`📂 DB Persistent Store configured at: ${DB_FILE}`);
    console.log(`======================================================\n`);
  });
}

startServer().catch((err) => {
  console.error("FATAL: Failed to initiate server core application:", err);
});
