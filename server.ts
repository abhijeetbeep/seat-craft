import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { db, uploadsDir } from './src/server/db';
import {
  attachCurrentUser,
  clearSessionCookie,
  createSessionForUser,
  deleteSession,
  hashPassword,
  requireAdmin,
  requireAuth,
  requireSameOriginOrCustomHeader,
  setSessionCookie,
  verifyPassword,
  type AuthenticatedRequest,
} from './src/server/auth';
import {
  calculateBookingTotal,
  canBookSeats,
  computeEventStats,
  validateEmail,
  validatePasswordStrength,
} from './src/lib/bookingRules';
import type { AdminStatus, BookingItem, EventCategory, EventItem, User } from './src/types';

const ALLOWED_CATEGORIES: EventCategory[] = [
  'Conference',
  'Workshop',
  'Campus Fest',
  'Concert',
  'Webinar',
];

function getAdminStatus(): AdminStatus {
  const row = db
    .prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")
    .get() as { count: number };
  const passcodeConfigured = Boolean(process.env.ADMIN_PASSCODE?.trim());
  return {
    hasAdmin: row.count > 0,
    passcodeConfigured,
  };
}

function isValidImageUrl(url: string): boolean {
  const trimmed = url.trim();
  if (trimmed.startsWith('/src/assets/images/') || trimmed.startsWith('/uploads/')) {
    return !trimmed.includes('..');
  }
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

function logActivity(actorName: string, actorRole: string, action: string, targetLabel: string): void {
  db.prepare(
    'INSERT INTO activity_logs (actor_name, actor_role, action, target_label, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(actorName, actorRole, action, targetLabel, new Date().toISOString());
}

function mapEventRow(row: Record<string, unknown>): EventItem {
  return {
    id: Number(row.id),
    title: String(row.title),
    category: row.category as EventCategory,
    description: String(row.description),
    venue: String(row.venue),
    city: String(row.city),
    eventDate: String(row.event_date),
    eventTime: String(row.event_time),
    totalSeats: Number(row.total_seats),
    bookedSeats: Number(row.booked_seats),
    price: Number(row.price),
    bannerUrl: String(row.banner_url),
    organizerId: row.organizer_id === null ? null : Number(row.organizer_id),
    status: row.status as EventItem['status'],
    createdAt: String(row.created_at),
  };
}

function mapBookingRow(row: Record<string, unknown>): BookingItem {
  return {
    id: Number(row.id),
    bookingCode: String(row.booking_code),
    eventId: Number(row.event_id),
    userId: Number(row.user_id),
    attendeeName: String(row.attendee_name),
    attendeeEmail: String(row.attendee_email),
    seats: Number(row.seats),
    totalAmount: Number(row.total_amount),
    status: row.status as BookingItem['status'],
    createdAt: String(row.created_at),
    eventTitle: String(row.event_title),
    eventDate: String(row.event_date),
    eventTime: String(row.event_time),
    venue: String(row.venue),
    city: String(row.city),
    category: row.category as EventCategory,
    bannerUrl: String(row.banner_url),
  };
}

async function startServer(): Promise<void> {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '4mb' }));
  app.use(attachCurrentUser);
  app.use('/api', requireSameOriginOrCustomHeader);

  // Safely serve uploaded event banners from data/uploads
  app.get('/uploads/:filename', (req, res) => {
    const filename = req.params.filename;
    if (!/^[a-zA-Z0-9_-]+\.(jpg|png|webp)$/.test(filename)) {
      res.status(400).json({ error: 'Invalid filename.' });
      return;
    }
    const resolved = path.resolve(uploadsDir, filename);
    if (!resolved.startsWith(uploadsDir + path.sep) || !fs.existsSync(resolved)) {
      res.status(404).json({ error: 'Banner not found.' });
      return;
    }
    res.sendFile(resolved);
  });

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  // Auth routes
  app.get('/api/auth/me', (req: AuthenticatedRequest, res) => {
    res.json({
      user: req.user ?? null,
      adminStatus: getAdminStatus(),
    });
  });

  app.post('/api/auth/register', (req, res) => {
    const { name, email, password } = req.body ?? {};
    const cleanName = typeof name === 'string' ? name.trim() : '';
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const rawPassword = typeof password === 'string' ? password : '';

    if (cleanName.length < 2 || cleanName.length > 80) {
      res.status(400).json({ error: 'Full name must be between 2 and 80 characters.' });
      return;
    }
    if (!validateEmail(cleanEmail)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }
    const pwCheck = validatePasswordStrength(rawPassword);
    if (!pwCheck.isValid) {
      res.status(400).json({ error: `Password requirements: ${pwCheck.errors.join(', ')}.` });
      return;
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
    if (existing) {
      res.status(409).json({ error: 'An account with this email already exists.' });
      return;
    }

    const passwordHash = hashPassword(rawPassword);
    const createdAt = new Date().toISOString();

    const info = db
      .prepare(
        "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, 'attendee', ?)"
      )
      .run(cleanName, cleanEmail, passwordHash, createdAt);

    const userId = Number(info.lastInsertRowid);
    const user: User = {
      id: userId,
      name: cleanName,
      email: cleanEmail,
      role: 'attendee',
      createdAt,
    };

    const token = createSessionForUser(userId);
    setSessionCookie(res, req, token);
    logActivity(cleanName, 'attendee', 'Registered new attendee account', cleanEmail);

    res.status(201).json({ user, adminStatus: getAdminStatus() });
  });

  app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body ?? {};
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const rawPassword = typeof password === 'string' ? password : '';

    if (!cleanEmail || !rawPassword) {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }

    const row = db
      .prepare('SELECT id, name, email, password_hash, role, created_at FROM users WHERE email = ?')
      .get(cleanEmail) as
      | {
          id: number;
          name: string;
          email: string;
          password_hash: string;
          role: 'attendee' | 'admin';
          created_at: string;
        }
      | undefined;

    if (!row || !verifyPassword(rawPassword, row.password_hash)) {
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    const token = createSessionForUser(row.id);
    setSessionCookie(res, req, token);

    const user: User = {
      id: row.id,
      name: row.name,
      email: row.email,
      role: row.role,
      createdAt: row.created_at,
    };

    logActivity(user.name, user.role, 'Signed in', user.email);
    res.json({ user, adminStatus: getAdminStatus() });
  });

  app.post('/api/auth/claim-admin', (req, res) => {
    const envPasscode = process.env.ADMIN_PASSCODE?.trim();
    if (envPasscode) {
      res.status(403).json({ error: 'Organizer setup is managed via server passcode.' });
      return;
    }

    const { name, email, password } = req.body ?? {};
    const cleanName = typeof name === 'string' ? name.trim() : '';
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const rawPassword = typeof password === 'string' ? password : '';

    if (cleanName.length < 2 || cleanName.length > 80) {
      res.status(400).json({ error: 'Organizer name must be between 2 and 80 characters.' });
      return;
    }
    if (!validateEmail(cleanEmail)) {
      res.status(400).json({ error: 'Please enter a valid organizer email.' });
      return;
    }
    const pwCheck = validatePasswordStrength(rawPassword);
    if (!pwCheck.isValid) {
      res.status(400).json({ error: `Password requirements: ${pwCheck.errors.join(', ')}.` });
      return;
    }

    const passwordHash = hashPassword(rawPassword);
    const createdAt = new Date().toISOString();

    try {
      db.exec('BEGIN IMMEDIATE');
      const countRow = db
        .prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")
        .get() as { count: number };

      if (countRow.count > 0) {
        db.exec('ROLLBACK');
        res.status(409).json({ error: 'An organizer admin account has already been claimed.' });
        return;
      }

      const existingEmail = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
      if (existingEmail) {
        db.exec('ROLLBACK');
        res.status(409).json({ error: 'Email already registered. Use a unique organizer email.' });
        return;
      }

      const info = db
        .prepare(
          "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)"
        )
        .run(cleanName, cleanEmail, passwordHash, createdAt);

      const userId = Number(info.lastInsertRowid);
      db.exec('COMMIT');

      const token = createSessionForUser(userId);
      setSessionCookie(res, req, token);
      logActivity(cleanName, 'admin', 'Claimed organizer admin workspace', cleanEmail);

      const user: User = {
        id: userId,
        name: cleanName,
        email: cleanEmail,
        role: 'admin',
        createdAt,
      };
      res.status(201).json({ user, adminStatus: getAdminStatus() });
    } catch (err) {
      try {
        db.exec('ROLLBACK');
      } catch {
        // ignore rollback error
      }
      console.error('Claim admin failed:', err);
      res.status(500).json({ error: 'Could not claim organizer workspace.' });
    }
  });

  app.post('/api/auth/admin-passcode', (req, res) => {
    const envPasscode = process.env.ADMIN_PASSCODE?.trim();
    if (!envPasscode) {
      res.status(400).json({ error: 'Server organizer passcode is not configured.' });
      return;
    }

    const { passcode, name, email } = req.body ?? {};
    const supplied = typeof passcode === 'string' ? passcode : '';

    const expectedDigest = crypto.createHash('sha256').update(envPasscode).digest();
    const suppliedDigest = crypto.createHash('sha256').update(supplied).digest();
    if (!crypto.timingSafeEqual(expectedDigest, suppliedDigest)) {
      res.status(401).json({ error: 'Invalid organizer passcode.' });
      return;
    }

    const cleanEmail =
      typeof email === 'string' && validateEmail(email)
        ? email.trim().toLowerCase()
        : 'organizer@seatcraft.local';
    const cleanName =
      typeof name === 'string' && name.trim().length >= 2 ? name.trim() : 'Lead Organizer';

    let row = db
      .prepare('SELECT id, name, email, role, created_at FROM users WHERE email = ?')
      .get(cleanEmail) as
      | { id: number; name: string; email: string; role: 'attendee' | 'admin'; created_at: string }
      | undefined;

    if (!row) {
      const createdAt = new Date().toISOString();
      const info = db
        .prepare(
          "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)"
        )
        .run(cleanName, cleanEmail, hashPassword(crypto.randomBytes(24).toString('hex')), createdAt);
      row = {
        id: Number(info.lastInsertRowid),
        name: cleanName,
        email: cleanEmail,
        role: 'admin',
        created_at: createdAt,
      };
    } else if (row.role !== 'admin') {
      db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(row.id);
      row.role = 'admin';
    }

    const token = createSessionForUser(row.id);
    setSessionCookie(res, req, token);
    logActivity(row.name, 'admin', 'Authenticated via organizer passcode', row.email);

    res.json({
      user: {
        id: row.id,
        name: row.name,
        email: row.email,
        role: 'admin',
        createdAt: row.created_at,
      },
      adminStatus: getAdminStatus(),
    });
  });

  app.post('/api/auth/logout', (req: AuthenticatedRequest, res) => {
    if (req.sessionToken) {
      deleteSession(req.sessionToken);
    }
    clearSessionCookie(res, req);
    res.json({ ok: true });
  });

  // Banner image upload (admin only)
  app.post('/api/upload', requireAdmin, (req: AuthenticatedRequest, res) => {
    const { dataUrl } = req.body ?? {};
    if (typeof dataUrl !== 'string') {
      res.status(400).json({ error: 'Image payload is required.' });
      return;
    }

    const match = /^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl);
    if (!match) {
      res.status(400).json({ error: 'Only PNG, JPEG, or WebP images are supported.' });
      return;
    }

    const mimeType = match[1];
    const buffer = Buffer.from(match[2], 'base64');
    if (buffer.byteLength > 2 * 1024 * 1024) {
      res.status(400).json({ error: 'Image exceeds maximum size of 2 MB.' });
      return;
    }

    const ext = mimeType === 'image/png' ? 'png' : mimeType === 'image/webp' ? 'webp' : 'jpg';
    const filename = `banner_${crypto.randomUUID().replace(/-/g, '')}.${ext}`;
    const targetPath = path.resolve(uploadsDir, filename);

    if (!targetPath.startsWith(uploadsDir + path.sep)) {
      res.status(400).json({ error: 'Invalid upload destination.' });
      return;
    }

    fs.writeFileSync(targetPath, buffer);
    res.status(201).json({ url: `/uploads/${filename}` });
  });

  // Event CRUD routes
  app.get('/api/events', (_req, res) => {
    const rows = db
      .prepare('SELECT * FROM events ORDER BY event_date ASC, event_time ASC, id DESC')
      .all() as Array<Record<string, unknown>>;
    res.json({ events: rows.map(mapEventRow) });
  });

  app.post('/api/events', requireAdmin, (req: AuthenticatedRequest, res) => {
    const {
      title,
      category,
      description,
      venue,
      city,
      eventDate,
      eventTime,
      totalSeats,
      price,
      bannerUrl,
    } = req.body ?? {};

    const cleanTitle = typeof title === 'string' ? title.trim() : '';
    const cleanCategory = ALLOWED_CATEGORIES.includes(category) ? category : null;
    const cleanDesc = typeof description === 'string' ? description.trim() : '';
    const cleanVenue = typeof venue === 'string' ? venue.trim() : '';
    const cleanCity = typeof city === 'string' ? city.trim() : '';
    const cleanDate = typeof eventDate === 'string' ? eventDate.trim() : '';
    const cleanTime = typeof eventTime === 'string' ? eventTime.trim() : '';
    const numSeats = Number(totalSeats);
    const numPrice = Number(price ?? 0);
    const cleanBanner =
      typeof bannerUrl === 'string' && isValidImageUrl(bannerUrl)
        ? bannerUrl.trim()
        : '/src/assets/images/hero_event_auditorium_1795591220190.jpg';

    if (cleanTitle.length < 3 || cleanTitle.length > 140) {
      res.status(400).json({ error: 'Event title must be 3 to 140 characters.' });
      return;
    }
    if (!cleanCategory) {
      res.status(400).json({ error: 'Select a valid event category.' });
      return;
    }
    if (cleanDesc.length < 10) {
      res.status(400).json({ error: 'Provide a description of at least 10 characters.' });
      return;
    }
    if (!cleanVenue || !cleanCity) {
      res.status(400).json({ error: 'Venue and city are required.' });
      return;
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(cleanDate) || !/^\d{2}:\d{2}$/.test(cleanTime)) {
      res.status(400).json({ error: 'Valid event date and time are required.' });
      return;
    }
    if (!Number.isInteger(numSeats) || numSeats < 1 || numSeats > 10000) {
      res.status(400).json({ error: 'Total seats must be an integer between 1 and 10,000.' });
      return;
    }
    if (!Number.isFinite(numPrice) || numPrice < 0 || numPrice > 10000) {
      res.status(400).json({ error: 'Ticket price must be between $0 and $10,000.' });
      return;
    }

    const createdAt = new Date().toISOString();
    const info = db
      .prepare(
        `INSERT INTO events (
          title, category, description, venue, city, event_date, event_time,
          total_seats, booked_seats, price, banner_url, organizer_id, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 'upcoming', ?)`
      )
      .run(
        cleanTitle,
        cleanCategory,
        cleanDesc,
        cleanVenue,
        cleanCity,
        cleanDate,
        cleanTime,
        numSeats,
        Math.round(numPrice * 100) / 100,
        cleanBanner,
        req.user!.id,
        createdAt
      );

    const row = db
      .prepare('SELECT * FROM events WHERE id = ?')
      .get(Number(info.lastInsertRowid)) as Record<string, unknown>;

    logActivity(req.user!.name, 'admin', 'Created event', cleanTitle);
    res.status(201).json({ event: mapEventRow(row) });
  });

  app.put('/api/events/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
    const eventId = Number(req.params.id);
    if (!Number.isInteger(eventId) || eventId <= 0) {
      res.status(400).json({ error: 'Invalid event ID.' });
      return;
    }

    const existing = db.prepare('SELECT * FROM events WHERE id = ?').get(eventId) as
      | Record<string, unknown>
      | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Event not found.' });
      return;
    }

    const {
      title,
      category,
      description,
      venue,
      city,
      eventDate,
      eventTime,
      totalSeats,
      price,
      bannerUrl,
      status,
    } = req.body ?? {};

    const cleanTitle = typeof title === 'string' ? title.trim() : String(existing.title);
    const cleanCategory = ALLOWED_CATEGORIES.includes(category)
      ? category
      : (existing.category as EventCategory);
    const cleanDesc =
      typeof description === 'string' ? description.trim() : String(existing.description);
    const cleanVenue = typeof venue === 'string' ? venue.trim() : String(existing.venue);
    const cleanCity = typeof city === 'string' ? city.trim() : String(existing.city);
    const cleanDate =
      typeof eventDate === 'string' ? eventDate.trim() : String(existing.event_date);
    const cleanTime =
      typeof eventTime === 'string' ? eventTime.trim() : String(existing.event_time);
    const numSeats = totalSeats !== undefined ? Number(totalSeats) : Number(existing.total_seats);
    const bookedSeats = Number(existing.booked_seats);
    const numPrice = price !== undefined ? Number(price) : Number(existing.price);
    const cleanBanner =
      typeof bannerUrl === 'string' && isValidImageUrl(bannerUrl)
        ? bannerUrl.trim()
        : String(existing.banner_url);
    const cleanStatus =
      status === 'upcoming' || status === 'completed' || status === 'cancelled'
        ? status
        : (existing.status as EventItem['status']);

    if (cleanTitle.length < 3 || cleanDesc.length < 10 || !cleanVenue || !cleanCity) {
      res.status(400).json({ error: 'All event fields must be valid.' });
      return;
    }
    if (!Number.isInteger(numSeats) || numSeats < bookedSeats) {
      res.status(400).json({
        error: `Total seats cannot be lower than already booked seats (${bookedSeats}).`,
      });
      return;
    }

    db.prepare(
      `UPDATE events
       SET title = ?, category = ?, description = ?, venue = ?, city = ?,
           event_date = ?, event_time = ?, total_seats = ?, price = ?,
           banner_url = ?, status = ?
       WHERE id = ?`
    ).run(
      cleanTitle,
      cleanCategory,
      cleanDesc,
      cleanVenue,
      cleanCity,
      cleanDate,
      cleanTime,
      numSeats,
      Math.round(numPrice * 100) / 100,
      cleanBanner,
      cleanStatus,
      eventId
    );

    // Notify attendees with confirmed bookings if schedule or venue changed
    if (
      cleanDate !== String(existing.event_date) ||
      cleanTime !== String(existing.event_time) ||
      cleanVenue !== String(existing.venue) ||
      cleanStatus !== String(existing.status)
    ) {
      const affected = db
        .prepare(
          "SELECT DISTINCT user_id, attendee_email FROM bookings WHERE event_id = ? AND status = 'confirmed'"
        )
        .all(eventId) as Array<{ user_id: number; attendee_email: string }>;
      const now = new Date().toISOString();
      const insNotif = db.prepare(
        `INSERT INTO notifications (user_id, booking_id, type, title, message, recipient_email, is_read, created_at)
         VALUES (?, NULL, 'event_updated', ?, ?, ?, 0, ?)`
      );
      for (const a of affected) {
        insNotif.run(
          a.user_id,
          `Schedule updated: ${cleanTitle}`,
          `Updated details: ${cleanDate} at ${cleanTime}, ${cleanVenue} (${cleanCity}). Status: ${cleanStatus}.`,
          a.attendee_email,
          now
        );
      }
    }

    const updated = db.prepare('SELECT * FROM events WHERE id = ?').get(eventId) as Record<
      string,
      unknown
    >;
    logActivity(req.user!.name, 'admin', 'Updated event details', cleanTitle);
    res.json({ event: mapEventRow(updated) });
  });

  app.delete('/api/events/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
    const eventId = Number(req.params.id);
    if (!Number.isInteger(eventId) || eventId <= 0) {
      res.status(400).json({ error: 'Invalid event ID.' });
      return;
    }

    const existing = db.prepare('SELECT title FROM events WHERE id = ?').get(eventId) as
      | { title: string }
      | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Event not found.' });
      return;
    }

    db.prepare('DELETE FROM events WHERE id = ?').run(eventId);
    logActivity(req.user!.name, 'admin', 'Deleted event', existing.title);
    res.json({ ok: true });
  });

  // Booking routes
  app.get('/api/bookings', requireAuth, (req: AuthenticatedRequest, res) => {
    const scope = req.query.scope;
    const isAdminAll = scope === 'all' && req.user!.role === 'admin';

    const query = `
      SELECT b.*, e.title AS event_title, e.event_date, e.event_time,
             e.venue, e.city, e.category, e.banner_url
      FROM bookings b
      JOIN events e ON e.id = b.event_id
      ${isAdminAll ? '' : 'WHERE b.user_id = ?'}
      ORDER BY b.created_at DESC
    `;

    const rows = (
      isAdminAll ? db.prepare(query).all() : db.prepare(query).all(req.user!.id)
    ) as Array<Record<string, unknown>>;

    res.json({ bookings: rows.map(mapBookingRow) });
  });

  app.post('/api/bookings', requireAuth, (req: AuthenticatedRequest, res) => {
    const { eventId, seats, attendeeName, attendeeEmail } = req.body ?? {};
    const numEventId = Number(eventId);
    const numSeats = Number(seats);
    const cleanName =
      typeof attendeeName === 'string' && attendeeName.trim().length >= 2
        ? attendeeName.trim()
        : req.user!.name;
    const cleanEmail =
      typeof attendeeEmail === 'string' && validateEmail(attendeeEmail)
        ? attendeeEmail.trim().toLowerCase()
        : req.user!.email;

    if (!Number.isInteger(numEventId) || numEventId <= 0) {
      res.status(400).json({ error: 'Valid event ID is required.' });
      return;
    }

    try {
      db.exec('BEGIN IMMEDIATE');
      const evRow = db.prepare('SELECT * FROM events WHERE id = ?').get(numEventId) as
        | Record<string, unknown>
        | undefined;

      if (!evRow) {
        db.exec('ROLLBACK');
        res.status(404).json({ error: 'Event not found.' });
        return;
      }

      const ev = mapEventRow(evRow);
      const seatCheck = canBookSeats(ev, numSeats);
      if (!seatCheck.ok) {
        db.exec('ROLLBACK');
        res.status(400).json({ error: seatCheck.reason });
        return;
      }

      const pricing = calculateBookingTotal(ev.price, numSeats);
      const bookingCode = `SC-${new Date().getFullYear()}-${crypto
        .randomInt(1000, 9999)
        .toString()}`;
      const createdAt = new Date().toISOString();

      db.prepare('UPDATE events SET booked_seats = booked_seats + ? WHERE id = ?').run(
        numSeats,
        ev.id
      );

      const bookingInfo = db
        .prepare(
          `INSERT INTO bookings (
            booking_code, event_id, user_id, attendee_name, attendee_email,
            seats, total_amount, status, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 'confirmed', ?)`
        )
        .run(
          bookingCode,
          ev.id,
          req.user!.id,
          cleanName,
          cleanEmail,
          numSeats,
          pricing.total,
          createdAt
        );

      const bookingId = Number(bookingInfo.lastInsertRowid);

      db.prepare(
        `INSERT INTO notifications (
          user_id, booking_id, type, title, message, recipient_email, is_read, created_at
        ) VALUES (?, ?, 'booking_confirmed', ?, ?, ?, 0, ?)`
      ).run(
        req.user!.id,
        bookingId,
        `Booking Confirmed: ${ev.title}`,
        `Pass ${bookingCode} issued for ${numSeats} seat${numSeats > 1 ? 's' : ''} on ${ev.eventDate} at ${ev.eventTime} (${ev.venue}, ${ev.city}).`,
        cleanEmail,
        createdAt
      );

      db.prepare(
        `INSERT INTO notifications (
          user_id, booking_id, type, title, message, recipient_email, is_read, created_at
        ) VALUES (?, ?, 'email_dispatch', ?, ?, ?, 0, ?)`
      ).run(
        req.user!.id,
        bookingId,
        `Confirmation Email Queued (${bookingCode})`,
        `Digital ticket receipt sent to ${cleanEmail} for ${ev.title}.`,
        cleanEmail,
        createdAt
      );

      logActivity(
        cleanName,
        req.user!.role,
        `Booked ${numSeats} seat${numSeats > 1 ? 's' : ''}`,
        `${ev.title} (${bookingCode})`
      );

      const createdBooking = db
        .prepare(
          `SELECT b.*, e.title AS event_title, e.event_date, e.event_time,
                  e.venue, e.city, e.category, e.banner_url
           FROM bookings b
           JOIN events e ON e.id = b.event_id
           WHERE b.id = ?`
        )
        .get(bookingId) as Record<string, unknown>;

      db.exec('COMMIT');
      res.status(201).json({ booking: mapBookingRow(createdBooking) });
    } catch (err) {
      try {
        db.exec('ROLLBACK');
      } catch {
        // ignore
      }
      console.error('Booking transaction failed:', err);
      res.status(500).json({ error: 'Unable to complete booking. Please retry.' });
    }
  });

  app.post('/api/bookings/:id/cancel', requireAuth, (req: AuthenticatedRequest, res) => {
    const bookingId = Number(req.params.id);
    if (!Number.isInteger(bookingId) || bookingId <= 0) {
      res.status(400).json({ error: 'Invalid booking ID.' });
      return;
    }

    try {
      db.exec('BEGIN IMMEDIATE');
      const row = db
        .prepare(
          `SELECT b.*, e.title AS event_title
           FROM bookings b
           JOIN events e ON e.id = b.event_id
           WHERE b.id = ?`
        )
        .get(bookingId) as
        | {
            id: number;
            booking_code: string;
            event_id: number;
            user_id: number;
            attendee_name: string;
            attendee_email: string;
            seats: number;
            status: string;
            event_title: string;
          }
        | undefined;

      if (!row) {
        db.exec('ROLLBACK');
        res.status(404).json({ error: 'Booking not found.' });
        return;
      }

      if (row.user_id !== req.user!.id && req.user!.role !== 'admin') {
        db.exec('ROLLBACK');
        res.status(403).json({ error: 'You do not have permission to cancel this booking.' });
        return;
      }

      if (row.status === 'cancelled') {
        db.exec('ROLLBACK');
        res.status(400).json({ error: 'Booking is already cancelled.' });
        return;
      }

      db.prepare("UPDATE bookings SET status = 'cancelled' WHERE id = ?").run(bookingId);
      db.prepare(
        'UPDATE events SET booked_seats = MAX(0, booked_seats - ?) WHERE id = ?'
      ).run(row.seats, row.event_id);

      const now = new Date().toISOString();
      db.prepare(
        `INSERT INTO notifications (
          user_id, booking_id, type, title, message, recipient_email, is_read, created_at
        ) VALUES (?, ?, 'booking_cancelled', ?, ?, ?, 0, ?)`
      ).run(
        row.user_id,
        bookingId,
        `Booking Cancelled: ${row.event_title}`,
        `Pass ${row.booking_code} (${row.seats} seat${row.seats > 1 ? 's' : ''}) was cancelled and seats were released back to inventory.`,
        row.attendee_email,
        now
      );

      logActivity(
        req.user!.name,
        req.user!.role,
        `Cancelled ${row.seats} seat${row.seats > 1 ? 's' : ''}`,
        `${row.event_title} (${row.booking_code})`
      );

      db.exec('COMMIT');
      res.json({ ok: true });
    } catch (err) {
      try {
        db.exec('ROLLBACK');
      } catch {
        // ignore
      }
      console.error('Cancel booking error:', err);
      res.status(500).json({ error: 'Unable to cancel booking.' });
    }
  });

  // Notifications
  app.get('/api/notifications', requireAuth, (req: AuthenticatedRequest, res) => {
    const isAdmin = req.user!.role === 'admin';
    const rows = (
      isAdmin
        ? db.prepare('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50').all()
        : db
            .prepare(
              'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
            )
            .all(req.user!.id)
    ) as Array<Record<string, unknown>>;

    res.json({
      notifications: rows.map((r) => ({
        id: Number(r.id),
        userId: Number(r.user_id),
        bookingId: r.booking_id === null ? null : Number(r.booking_id),
        type: r.type,
        title: String(r.title),
        message: String(r.message),
        recipientEmail: String(r.recipient_email),
        isRead: Boolean(r.is_read),
        createdAt: String(r.created_at),
      })),
    });
  });

  app.post('/api/notifications/:id/read', requireAuth, (req: AuthenticatedRequest, res) => {
    const notifId = Number(req.params.id);
    if (!Number.isInteger(notifId) || notifId <= 0) {
      res.status(400).json({ error: 'Invalid notification ID.' });
      return;
    }

    if (req.user!.role === 'admin') {
      db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(notifId);
    } else {
      db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?').run(
        notifId,
        req.user!.id
      );
    }
    res.json({ ok: true });
  });

  app.post('/api/notifications/read-all', requireAuth, (req: AuthenticatedRequest, res) => {
    if (req.user!.role === 'admin') {
      db.prepare('UPDATE notifications SET is_read = 1').run();
    } else {
      db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.user!.id);
    }
    res.json({ ok: true });
  });

  // Analytics & Activity Feed
  app.get('/api/analytics', (req: AuthenticatedRequest, res) => {
    const eventRows = db
      .prepare('SELECT * FROM events ORDER BY event_date ASC')
      .all() as Array<Record<string, unknown>>;
    const events = eventRows.map(mapEventRow);
    const summary = computeEventStats(events);

    const activityRows = db
      .prepare('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 20')
      .all() as Array<Record<string, unknown>>;

    const bookingCounts = db
      .prepare(
        `SELECT
           COUNT(*) AS totalBookings,
           SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END) AS confirmedBookings,
           SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelledBookings
         FROM bookings`
      )
      .get() as {
      totalBookings: number;
      confirmedBookings: number | null;
      cancelledBookings: number | null;
    };

    const userCountRow = db.prepare('SELECT COUNT(*) AS count FROM users').get() as {
      count: number;
    };

    res.json({
      summary,
      registrationTotals: {
        totalBookings: bookingCounts.totalBookings ?? 0,
        confirmedBookings: bookingCounts.confirmedBookings ?? 0,
        cancelledBookings: bookingCounts.cancelledBookings ?? 0,
        registeredUsers: userCountRow.count,
      },
      activityLogs:
        req.user?.role === 'admin'
          ? activityRows.map((a) => ({
              id: Number(a.id),
              actorName: String(a.actor_name),
              actorRole: String(a.actor_role),
              action: String(a.action),
              targetLabel: String(a.target_label),
              createdAt: String(a.created_at),
            }))
          : activityRows.slice(0, 8).map((a) => ({
              id: Number(a.id),
              actorName: a.actor_role === 'admin' ? 'Organizer' : 'Platform Activity',
              actorRole: String(a.actor_role),
              action: String(a.action),
              targetLabel: String(a.target_label),
              createdAt: String(a.created_at),
            })),
    });
  });

  // Vite dev middleware or static serving
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const port = Number(process.env.PORT || 3000);
  app.listen(port, '0.0.0.0', () => {
    console.log(`SeatCraft server listening on http://localhost:${port}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start SeatCraft server:', err);
  process.exit(1);
});
