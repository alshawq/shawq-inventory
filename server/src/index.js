
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { z, ZodError } from 'zod';

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 3001);

if (
  !process.env.DATABASE_URL ||
  !process.env.JWT_SECRET ||
  process.env.JWT_SECRET.length < 32
) {
  console.error(
    'Set DATABASE_URL and a JWT_SECRET of at least 32 characters in server/.env'
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'true'
    ? { rejectUnauthorized: true }
    : undefined
});

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin: (process.env.CORS_ORIGIN || 'http://localhost:5173')
    .split(',')
    .map(s => s.trim())
}));
app.use(express.json({ limit: '100kb' }));

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const parse = (schema, body) => schema.parse(body);

const text = z.string().trim().min(1).max(250);
const opt = z.string().trim().max(250).optional().default('');
const money = z.coerce.number().finite().min(0).max(999999999);
const qty = z.coerce.number().int().min(0).max(999999999);
const id = z.coerce.number().int().positive();

const productSchema = z.object({
  name: text,
  sku: text,
  category: opt,
  price: money,
  cost: money,
  stock: qty,
  min: qty,
  warehouseId: id.nullable().optional()
});

const supplierSchema = z.object({
  name: text,
  phone: opt,
  email: z.union([
    z.literal(''),
    z.string().email()
  ]).optional().default('')
});

const warehouseSchema = z.object({
  name: text,
  location: opt
});

const linesSchema = z.array(
  z.object({
    productId: id,
    quantity: z.coerce.number().int().positive().max(100000)
  })
).min(1).max(100);

const invoiceSchema = z.object({
  customer: opt,
  items: linesSchema
});

const purchaseSchema = z.object({
  supplierId: id,
  items: linesSchema
});

const safe = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const auth = (req, res, next) => {
  try {
    const token = (req.headers.authorization || '')
      .match(/^Bearer (.+)$/)?.[1];

    if (!token) {
      return res.status(401).json({
        error: 'تسجيل الدخول مطلوب'
      });
    }

    req.user = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256']
    });

    next();
  } catch {
    return res.status(401).json({
      error: 'جلسة غير صالحة'
    });
  }
};

const q = (sql, args = []) => pool.query(sql, args);

app.get('/api/health', safe(async (req, res) => {
  await q('SELECT 1');
  res.json({ ok: true });
}));

// تسجيل الدخول - تم تصحيح password_hash
app.post('/api/auth/login', authLimit, safe(async (req, res) => {
  const body = parse(
    z.object({
      email: z.string().email(),
      password: z.string().min(1)
    }),
    req.body
  );

  const { rows } = await q(
    'SELECT * FROM users WHERE email=$1',
    [body.email.toLowerCase()]
  );

  const user = rows[0];

  if (
    !user ||
    !user.password_hash ||
    !await bcrypt.compare(body.password, user.password_hash)
  ) {
    return res.status(401).json({
      error: 'بيانات الدخول غير صحيحة'
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    process.env.JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: '8h'
    }
  );

  res.json({
    token,
    user: {
      email: user.email,
      role: user.role
    }
  });
}));

app.use('/api', auth);

// جلب جميع بيانات النظام
app.get('/api/state', safe(async (req, res) => {
  const [ps, ws, ss, inv, pur] = await Promise.all([
    q(`
      SELECT p.*, w.name AS warehouse
      FROM products p
      LEFT JOIN warehouses w ON w.id = p.warehouse_id
      WHERE p.active = true
      ORDER BY p.id
    `),
    q('SELECT * FROM warehouses ORDER BY id'),
    q('SELECT * FROM suppliers ORDER BY id'),
    q(`
      SELECT i.*, ii.product_id AS "productId", ii.quantity
      FROM invoices i
      LEFT JOIN LATERAL (
        SELECT product_id, quantity
        FROM invoice_items
        WHERE invoice_id = i.id
        ORDER BY id
        LIMIT 1
      ) ii ON true
      ORDER BY i.id DESC
    `),
    q(`
      SELECT p.*, s.name AS supplier,
             pi.product_id AS "productId", pi.quantity
      FROM purchases p
      LEFT JOIN suppliers s ON s.id = p.supplier_id
      LEFT JOIN LATERAL (
        SELECT product_id, quantity
        FROM purchase_items
        WHERE purchase_id = p.id
        ORDER BY id
        LIMIT 1
      ) pi ON true
      ORDER BY p.id DESC
    `)
  ]);

  res.json({
    products: ps.rows.map(x => ({
      id: +x.id,
      name: x.name,
      sku: x.sku,
      category: x.category,
      price: +x.price,
      cost: +x.cost,
      stock: x.stock,
      min: x.min_stock,
      warehouse: x.warehouse || '',
      warehouseId: x.warehouse_id ? +x.warehouse_id : null
    })),
    warehouses: ws.rows.map(x => ({ ...x, id: +x.id })),
    suppliers: ss.rows.map(x => ({ ...x, id: +x.id })),
    invoices: inv.rows.map(x => ({
      ...x,
      id: +x.id,
      productId: x.productId == null ? null : +x.productId,
      quantity: x.quantity,
      total: +x.total,
      cost: +x.cost,
      date: new Date(x.date).toISOString().slice(0, 10)
    })),
    purchases: pur.rows.map(x => ({
      ...x,
      id: +x.id,
      productId: x.productId == null ? null : +x.productId,
      quantity: x.quantity,
      total: +x.total,
      date: new Date(x.date).toISOString().slice(0, 10)
    }))
  });
}));

// المنتجات
app.post('/api/products', safe(async (req, res) => {
  const b = parse(productSchema, req.body);

  const { rows } = await q(
    `INSERT INTO products
      (name, sku, category, price, cost, stock, min_stock, warehouse_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING id`,
    [
      b.name, b.sku, b.category || 'عام',
      b.price, b.cost, b.stock, b.min,
      b.warehouseId || null
    ]
  );

  res.status(201).json(rows[0]);
}));

app.put('/api/products/:id', safe(async (req, res) => {
  const b = parse(productSchema, req.body);

  const result = await q(
    `UPDATE products
     SET name=$1, sku=$2, category=$3,
         price=$4, cost=$5, min_stock=$6, warehouse_id=$7
     WHERE id=$8 AND active=true
     RETURNING id`,
    [
      b.name, b.sku, b.category || 'عام',
      b.price, b.cost, b.min,
      b.warehouseId || null, req.params.id
    ]
  );

  if (!result.rowCount) {
    return res.status(404).json({
      error: 'المنتج غير موجود'
    });
  }

  res.json(result.rows[0]);
}));

app.delete('/api/products/:id', safe(async (req, res) => {
  const result = await q(
    `UPDATE products
     SET active=false
     WHERE id=$1 AND active=true
     RETURNING id`,
    [req.params.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({
      error: 'المنتج غير موجود'
    });
  }

  res.json({ ok: true });
}));

// الموردون والمستودعات
for (const [kind, table, schema, cols] of [
  ['suppliers', 'suppliers', supplierSchema, ['name', 'phone', 'email']],
  ['warehouses', 'warehouses', warehouseSchema, ['name', 'location']]
]) {
  app.post('/api/' + kind, safe(async (req, res) => {
    const b = parse(schema, req.body);
    const vals = cols.map(k => b[k]);

    const result = await q(
      `INSERT INTO ${table}(${cols.join(',')})
       VALUES (${cols.map((_, i) => '$' + (i + 1)).join(',')})
       RETURNING id`,
      vals
    );

    res.status(201).json(result.rows[0]);
  }));

  app.put('/api/' + kind + '/:id', safe(async (req, res) => {
    const b = parse(schema, req.body);
    const vals = cols.map(k => b[k]);

    const result = await q(
      `UPDATE ${table}
       SET ${cols.map((c, i) => c + '=$' + (i + 1)).join(',')}
       WHERE id=$${cols.length + 1}
       RETURNING id`,
      [...vals, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'السجل غير موجود'
      });
    }

    res.json(result.rows[0]);
  }));

  app.delete('/api/' + kind + '/:id', safe(async (req, res) => {
    const result = await q(
      `DELETE FROM ${table} WHERE id=$1 RETURNING id`,
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'السجل غير موجود'
      });
    }

    res.json({ ok: true });
  }));
}

// معاملات قاعدة البيانات
async function transaction(fn) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

// إنشاء فواتير البيع
app.post('/api/invoices', safe(async (req, res) => {
  const b = parse(invoiceSchema, req.body);

  const result = await transaction(async client => {
    const merged = new Map();

    for (const item of b.items) {
      merged.set(
        item.productId,
        (merged.get(item.productId) || 0) + item.quantity
      );
    }

    let total = 0;
    let cost = 0;
    const lines = [];

    for (const [pid, quantity] of merged) {
      const r = await client.query(
        'SELECT * FROM products WHERE id=$1 AND active=true FOR UPDATE',
        [pid]
      );

      const product = r.rows[0];

      if (!product) {
        throw Object.assign(new Error('منتج غير موجود'), {
          status: 400
        });
      }

      if (product.stock < quantity) {
        throw Object.assign(
          new Error('الكمية غير متوفرة: ' + product.name),
          { status: 400 }
        );
      }

      total += Number(product.price) * quantity;
      cost += Number(product.cost) * quantity;
      lines.push({ product, quantity });
    }

    const number =
      'INV-' + Date.now() + '-' + Math.floor(Math.random() * 10000);

    const ir = await client.query(
      `INSERT INTO invoices
       (number, customer, total, cost, created_by)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id`,
      [number, b.customer || 'عميل نقدي', total, cost, req.user.id]
    );

    const invoiceId = ir.rows[0].id;

    for (const { product, quantity } of lines) {
      await client.query(
        `INSERT INTO invoice_items
         (invoice_id, product_id, product_name, quantity, unit_price, unit_cost)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [
          invoiceId, product.id, product.name,
          quantity, product.price, product.cost
        ]
      );

      await client.query(
        'UPDATE products SET stock=stock-$1 WHERE id=$2',
        [quantity, product.id]
      );

      await client.query(
        `INSERT INTO stock_movements
         (product_id, product_name, delta, reason, reference_id)
         VALUES ($1,$2,$3,$4,$5)`,
        [product.id, product.name, -quantity, 'sale', invoiceId]
      );
    }

    return { id: invoiceId, number, total, cost };
  });

  res.status(201).json(result);
}));

// تسجيل المشتريات
app.post('/api/purchases', safe(async (req, res) => {
  const b = parse(purchaseSchema, req.body);

  const result = await transaction(async client => {
    const sr = await client.query(
      'SELECT name FROM suppliers WHERE id=$1',
      [b.supplierId]
    );

    if (!sr.rowCount) {
      throw Object.assign(new Error('المورد غير موجود'), {
        status: 400
      });
    }

    const merged = new Map();

    for (const item of b.items) {
      merged.set(
        item.productId,
        (merged.get(item.productId) || 0) + item.quantity
      );
    }

    let total = 0;
    const lines = [];

    for (const [pid, quantity] of merged) {
      const r = await client.query(
        'SELECT * FROM products WHERE id=$1 AND active=true FOR UPDATE',
        [pid]
      );

      if (!r.rowCount) {
        throw Object.assign(new Error('منتج غير موجود'), {
          status: 400
        });
      }

      const product = r.rows[0];
      total += Number(product.cost) * quantity;
      lines.push({ product, quantity });
    }

    const pr = await client.query(
      `INSERT INTO purchases
       (supplier_id, supplier_name, total, created_by)
       VALUES ($1,$2,$3,$4)
       RETURNING id`,
      [b.supplierId, sr.rows[0].name, total, req.user.id]
    );

    const purchaseId = pr.rows[0].id;

    for (const { product, quantity } of lines) {
      await client.query(
        `INSERT INTO purchase_items
         (purchase_id, product_id, product_name, quantity, unit_cost)
         VALUES ($1,$2,$3,$4,$5)`,
        [
          purchaseId, product.id, product.name,
          quantity, product.cost
        ]
      );

      await client.query(
        'UPDATE products SET stock=stock+$1 WHERE id=$2',
        [quantity, product.id]
      );

      await client.query(
        `INSERT INTO stock_movements
         (product_id, product_name, delta, reason, reference_id)
         VALUES ($1,$2,$3,$4,$5)`,
        [product.id, product.name, quantity, 'purchase', purchaseId]
      );
    }

    return { id: purchaseId, total };
  });

  res.status(201).json(result);
}));

// تفاصيل الفاتورة
app.get('/api/invoices/:id', safe(async (req, res) => {
  const invoice = await q(
    'SELECT * FROM invoices WHERE id=$1',
    [req.params.id]
  );

  if (!invoice.rowCount) {
    return res.status(404).json({
      error: 'الفاتورة غير موجودة'
    });
  }

  const items = await q(
    `SELECT product_name, quantity, unit_price, unit_cost
     FROM invoice_items
     WHERE invoice_id=$1
     ORDER BY id`,
    [req.params.id]
  );

  res.json({
    invoice: invoice.rows[0],
    items: items.rows
  });
}));

// سجل حركة المخزون
app.get('/api/movements', safe(async (req, res) => {
  const result = await q(
    'SELECT * FROM stock_movements ORDER BY id DESC LIMIT 300'
  );

  res.json(result.rows);
}));

// معالجة الأخطاء
app.use((err, req, res, next) => {
  if (err instanceof ZodError) {
    return res.status(400).json({
      error: err.issues
        .map(x => x.path.join('.') + ': ' + x.message)
        .join('؛ ')
    });
  }

  if (err.code === '23505') {
    return res.status(409).json({
      error: 'الاسم أو الرمز مستخدم مسبقًا'
    });
  }

  if (err.code === '23503') {
    return res.status(409).json({
      error: 'لا يمكن حذف سجل مرتبط ببيانات أخرى'
    });
  }

  if (err.code === '22P02') {
    return res.status(400).json({
      error: 'معرّف غير صحيح'
    });
  }

  console.error(err);

  res.status(err.status || 500).json({
    error: err.status ? err.message : 'حدث خطأ في الخادم'
  });
});

// تهيئة قاعدة البيانات وإنشاء حساب المدير
async function start() {
  await pool.query('SELECT 1');

  const schema = await fs.readFile(
    fileURLToPath(new URL('../schema.sql', import.meta.url)),
    'utf8'
  );

  await pool.query(schema);

  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || '';

  if (email && password.length >= 12) {
    const existing = await q(
      'SELECT id FROM users WHERE email=$1',
      [email]
    );

    if (!existing.rowCount) {
      await q(
        'INSERT INTO users(email,password_hash) VALUES($1,$2)',
        [email, await bcrypt.hash(password, 12)]
      );
    }
  } else {
    console.warn(
      'Set ADMIN_EMAIL and ADMIN_PASSWORD (12+ characters) to create the admin account'
    );
  }

  app.listen(port, () => {
    console.log(`SHAWQ Inventory API on http://localhost:${port}`);
  });
}

start().catch(error => {
  console.error('Server failed to start:', error.message);
  process.exit(1);
});
