// sync-db.js - Direct SQLite bridge to BriefBay marketplace
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DB_PATH = path.resolve('c:/Users/Burhan Khan/Desktop/BreifBay/prisma/dev.db');

function getDb() {
  if (!fs.existsSync(DB_PATH)) {
    console.warn(`[Sync] Warning: BriefBay database not found at ${DB_PATH}`);
    return null;
  }
  return new DatabaseSync(DB_PATH);
}

function syncUserToBriefBay(user) {
  const db = getDb();
  if (!db) return { success: false, reason: 'Database file not found' };

  try {
    const email = (user.email || '').trim().toLowerCase();
    if (!email) return { success: false, reason: 'Email is required' };

    const role = user.role === 'FREELANCER' ? 'FREELANCER' : 'CLIENT';
    const name = user.username || user.name || (email.split('@')[0]);
    const image = user.avatar || `https://api.dicebear.com/7.x/identicon/svg?seed=${encodeURIComponent(user.username || email)}`;
    const nowIso = new Date().toISOString();

    // Check if user already exists
    const existing = db.prepare('SELECT id, role FROM User WHERE email = ?').get(email);
    let userId;

    if (existing) {
      userId = existing.id;
      db.prepare(`
        UPDATE User 
        SET role = ?, name = COALESCE(name, ?), updatedAt = ? 
        WHERE id = ?
      `).run(role, name, nowIso, userId);
      console.log(`[Sync] Updated existing user ${email} (${userId})`);
    } else {
      userId = crypto.randomUUID();
      db.prepare(`
        INSERT INTO User (id, name, email, emailVerified, image, role, displayCurrency, preferredLanguage, theme, status, createdAt, updatedAt)
        VALUES (?, ?, ?, ?, ?, ?, 'INR', 'en', 'system', 'ACTIVE', ?, ?)
      `).run(userId, name, email, nowIso, image, role, nowIso, nowIso);
      console.log(`[Sync] Created new user in BriefBay dev.db: ${email} (${userId})`);
    }

    // Upsert Profile
    if (role === 'CLIENT') {
      const existingProfile = db.prepare('SELECT id FROM ClientProfile WHERE userId = ?').get(userId);
      const discountNote = user.isFirst15 ? 'First 15 VIP Client (25% Discount Voucher Unlocked)' : 'Early Access Client';
      if (!existingProfile) {
        const profileId = crypto.randomUUID();
        db.prepare(`
          INSERT INTO ClientProfile (id, userId, niche, primaryService, companyName, timezone, onboardingStep, isCompleted, createdAt, updatedAt)
          VALUES (?, ?, ?, 'Video Editing & Web Dev', ?, 'Asia/Kolkata', 1, 1, ?, ?)
        `).run(profileId, userId, discountNote, name + ' Productions', nowIso, nowIso);
      } else {
        db.prepare(`
          UPDATE ClientProfile SET niche = ?, updatedAt = ? WHERE userId = ?
        `).run(discountNote, nowIso, userId);
      }
    } else {
      const existingProfile = db.prepare('SELECT id FROM FreelancerProfile WHERE userId = ?').get(userId);
      const badges = user.isFirst15 
        ? JSON.stringify(['FEATURED_PROMOTED_GIG', 'FOUNDING_TALENT', 'FAST_RESPONDER', 'EARLY_ACCESS_VIP'])
        : JSON.stringify(['FOUNDING_TALENT', 'FAST_RESPONDER']);
      const headline = user.isFirst15 
        ? '🌟 Founding Top Talent (Featured Early Access Work)'
        : '🚀 Founding Freelancer & Specialist';
      if (!existingProfile) {
        const profileId = crypto.randomUUID();
        db.prepare(`
          INSERT INTO FreelancerProfile (id, userId, headline, bio, primarySkill, hourlyRatePaise, weeklyCapacityHours, languages, timezone, sellerLevel, isAvailableNow, ratingAvg, ratingCount, onTimeRate, repeatHireRate, responseMinutes, kycStatus, proposalCredits, badgesJson, createdAt, updatedAt)
          VALUES (?, ?, ?, 'Pre-release registered talent on BriefBay early access.', 'Content & Software Development', 60000, 40, 'English, Hindi', 'Asia/Kolkata', 'NEW', 1, 5.0, 0, 100.0, 0.0, 30, 'VERIFIED', 30, ?, ?, ?)
        `).run(profileId, userId, headline, badges, nowIso, nowIso);
      } else {
        db.prepare(`
          UPDATE FreelancerProfile SET headline = ?, badgesJson = ?, updatedAt = ? WHERE userId = ?
        `).run(headline, badges, nowIso, userId);
      }
    }

    // Add Audit Log
    try {
      const logId = crypto.randomUUID();
      const perkDesc = user.perk || (user.isFirst15 ? (role === 'CLIENT' ? '25% OFF on first purchase' : 'Featured and promoted gig') : 'Standard Early Access');
      db.prepare(`
        INSERT INTO AuditLog (id, userId, action, details, ipAddress, createdAt)
        VALUES (?, ?, 'PRE_RELEASE_ONBOARDING', ?, '127.0.0.1', ?)
      `).run(logId, userId, JSON.stringify({
        preReleaseUsername: user.username,
        rank: user.rank,
        isFirst15: user.isFirst15,
        perk: perkDesc,
        registeredAt: user.createdAt || nowIso
      }), nowIso);
    } catch (e) {
      console.warn('[Sync] Non-critical AuditLog notice:', e.message);
    }

    // Add Welcome Notification
    try {
      const notifId = crypto.randomUUID();
      const perkDesc = user.perk || (user.isFirst15 ? (role === 'CLIENT' ? '25% OFF first purchase' : 'Featured Gigs & Work promotion') : 'Early Access Spot');
      const title = user.isFirst15 ? '⭐ Founder VIP Offer Active!' : '🎉 Welcome to BriefBay Early Access!';
      const msg = `Your pre-release registration has been connected. Benefit: ${perkDesc}.`;
      db.prepare(`
        INSERT INTO Notification (id, userId, title, message, type, isRead, createdAt)
        VALUES (?, ?, ?, ?, 'SYSTEM', 0, ?)
      `).run(notifId, userId, title, msg, nowIso);
    } catch (e) {
      console.warn('[Sync] Non-critical Notification notice:', e.message);
    }

    db.close();
    return { success: true, userId };
  } catch (err) {
    console.error('[Sync] Error syncing user to BriefBay:', err);
    try { db.close(); } catch {}
    return { success: false, error: err.message };
  }
}

function updateUserVipStatus(email, isFirst15, newPerk) {
  const db = getDb();
  if (!db) return { success: false, reason: 'Database file not found' };

  try {
    const user = db.prepare('SELECT id, role FROM User WHERE email = ?').get(email);
    if (!user) {
      db.close();
      return { success: false, reason: 'User not found in marketplace DB' };
    }

    const nowIso = new Date().toISOString();
    if (user.role === 'CLIENT') {
      const niche = isFirst15 ? 'First 15 VIP Client (25% Discount Voucher Unlocked)' : 'Early Access Client';
      db.prepare('UPDATE ClientProfile SET niche = ?, updatedAt = ? WHERE userId = ?').run(niche, nowIso, user.id);
    } else {
      const badges = isFirst15 
        ? JSON.stringify(['FEATURED_PROMOTED_GIG', 'FOUNDING_TALENT', 'FAST_RESPONDER', 'EARLY_ACCESS_VIP'])
        : JSON.stringify(['FOUNDING_TALENT', 'FAST_RESPONDER']);
      const headline = isFirst15 
        ? '🌟 Founding Top Talent (Featured Early Access Work)'
        : '🚀 Founding Freelancer & Specialist';
      db.prepare('UPDATE FreelancerProfile SET headline = ?, badgesJson = ?, updatedAt = ? WHERE userId = ?').run(headline, badges, nowIso, user.id);
    }

    // Add Audit Log
    const logId = crypto.randomUUID();
    db.prepare(`
      INSERT INTO AuditLog (id, userId, action, details, ipAddress, createdAt)
      VALUES (?, ?, 'VIP_STATUS_CHANGED', ?, '127.0.0.1', ?)
    `).run(logId, user.id, JSON.stringify({ isFirst15, perk: newPerk, timestamp: nowIso }), nowIso);

    db.close();
    return { success: true };
  } catch (err) {
    console.error('[Sync] Error updating VIP status:', err);
    try { db.close(); } catch {}
    return { success: false, error: err.message };
  }
}

function deleteUserFromBriefBay(email) {
  const db = getDb();
  if (!db) return { success: false, reason: 'Database file not found' };

  try {
    const normalized = (email || '').trim().toLowerCase();
    const user = db.prepare('SELECT id FROM User WHERE email = ?').get(normalized);
    if (!user) {
      db.close();
      return { success: true, message: 'User was not in dev.db' };
    }

    db.prepare('DELETE FROM ClientProfile WHERE userId = ?').run(user.id);
    db.prepare('DELETE FROM FreelancerProfile WHERE userId = ?').run(user.id);
    db.prepare('DELETE FROM AuditLog WHERE userId = ?').run(user.id);
    db.prepare('DELETE FROM Notification WHERE userId = ?').run(user.id);
    db.prepare('DELETE FROM User WHERE id = ?').run(user.id);

    db.close();
    return { success: true };
  } catch (err) {
    console.error('[Sync] Error deleting user from BriefBay:', err);
    try { db.close(); } catch {}
    return { success: false, error: err.message };
  }
}

function syncAllUsers(users) {
  let successCount = 0;
  for (const u of users) {
    const res = syncUserToBriefBay(u);
    if (res.success) successCount++;
  }
  return { success: true, total: users.length, synced: successCount };
}

module.exports = {
  syncUserToBriefBay,
  updateUserVipStatus,
  deleteUserFromBriefBay,
  syncAllUsers,
  getDb
};
