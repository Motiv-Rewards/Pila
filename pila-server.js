import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import { createClient } from '@libsql/client'
import { v4 as uuidv4 } from 'uuid'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SECRET = 'pila-secret-2024'
const ADMIN_SECRET = 'pila-admin-2024'

const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_TOKEN
})

await db.executeMultiple(`
  CREATE TABLE IF NOT EXISTS pila_users (
    id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, studio TEXT,
    password TEXT, birthday TEXT, points INTEGER DEFAULT 0,
    totalClasses INTEGER DEFAULT 0, currentStreak INTEGER DEFAULT 0,
    longestStreak INTEGER DEFAULT 0, lastClassWeek INTEGER,
    lastClassDate TEXT, earnedMilestones TEXT DEFAULT '[]',
    friends TEXT DEFAULT '[]',
    joinedAt TEXT, moodHistory TEXT DEFAULT '[]', classDates TEXT DEFAULT '[]'
  );
  CREATE TABLE IF NOT EXISTS pila_activity (
    id TEXT PRIMARY KEY, userId TEXT, type TEXT, label TEXT,
    points INTEGER, createdAt TEXT
  );
  CREATE TABLE IF NOT EXISTS pila_posts (
    id TEXT PRIMARY KEY, userId TEXT, userName TEXT, caption TEXT,
    imageData TEXT, visibility TEXT, classType TEXT,
    userStats TEXT, likes TEXT DEFAULT '[]', comments TEXT DEFAULT '[]',
    createdAt TEXT
  );
  CREATE TABLE IF NOT EXISTS pila_friend_requests (
    id TEXT PRIMARY KEY, fromId TEXT, toId TEXT, status TEXT, createdAt TEXT
  );
  CREATE TABLE IF NOT EXISTS pila_notifications (
    id TEXT PRIMARY KEY, userId TEXT, type TEXT, message TEXT,
    fromName TEXT, read INTEGER DEFAULT 0, createdAt TEXT
  );
`)

const app = express()
app.use(cors())
app.use(express.json({ limit: '10mb' }))
app.use(express.static(path.join(__dirname)))

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'No token' })
  try { req.user = jwt.verify(token, SECRET); next() }
  catch { res.status(401).json({ error: 'Invalid token' }) }
}

function sanitize(u) { if (!u) return null; const { password, ...rest } = u; return rest }

function parseUser(row) {
  if (!row) return null
  return { ...row, points: Number(row.points), totalClasses: Number(row.totalClasses),
    currentStreak: Number(row.currentStreak), longestStreak: Number(row.longestStreak),
    earnedMilestones: JSON.parse(row.earnedMilestones || '[]'),
    friends: JSON.parse(row.friends || '[]'),
    moodHistory: JSON.parse(row.moodHistory || '[]'),
    classDates: JSON.parse(row.classDates || '[]') }
}

async function getUser(id) {
  const r = await db.execute({ sql: 'SELECT * FROM pila_users WHERE id=?', args: [id] })
  return parseUser(r.rows[0])
}

async function getUserByEmail(email) {
  const r = await db.execute({ sql: 'SELECT * FROM pila_users WHERE email=?', args: [email.toLowerCase()] })
  return parseUser(r.rows[0])
}

async function saveUser(u) {
  await db.execute({
    sql: `INSERT OR REPLACE INTO pila_users (id,name,email,studio,password,birthday,points,totalClasses,
          currentStreak,longestStreak,lastClassWeek,lastClassDate,earnedMilestones,friends,joinedAt,moodHistory,classDates)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    args: [u.id,u.name,u.email,u.studio||'',u.password,u.birthday||'',u.points,u.totalClasses,
           u.currentStreak,u.longestStreak,u.lastClassWeek||null,u.lastClassDate||null,
           JSON.stringify(u.earnedMilestones||[]),JSON.stringify(u.friends||[]),
           u.joinedAt,JSON.stringify(u.moodHistory||[]),JSON.stringify(u.classDates||[])]
  })
}

async function addNotif(userId, type, message, fromName) {
  await db.execute({
    sql: 'INSERT INTO pila_notifications (id,userId,type,message,fromName,read,createdAt) VALUES (?,?,?,?,?,0,?)',
    args: [uuidv4(), userId, type, message, fromName||'', new Date().toISOString()]
  })
}

function checkMilestones(user) {
  const ms = [1,5,10,25,50,100]; const earned = []
  for (const m of ms) {
    if (user.totalClasses >= m && !user.earnedMilestones.includes(m)) {
      user.earnedMilestones.push(m); earned.push(m)
    }
  }
  return earned
}

// ── SIGNUP ──
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, studio, password, birthday } = req.body
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' })
    if (await getUserByEmail(email)) return res.status(409).json({ error: 'Email already registered' })
    const hashed = await bcrypt.hash(password, 10)
    const user = { id: uuidv4(), name, email: email.toLowerCase(), studio: studio||'',
      password: hashed, birthday: birthday||'', points: 0, totalClasses: 0,
      currentStreak: 0, longestStreak: 0, lastClassWeek: null, lastClassDate: null,
      earnedMilestones: [], friends: [], joinedAt: new Date().toISOString(),
      moodHistory: [], classDates: [] }
    await saveUser(user)
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' })
    res.json({ token, user: sanitize(user) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body
    const user = await getUserByEmail(email)
    if (!user) return res.status(401).json({ error: 'No account with that email' })
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Wrong password' })
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' })
    res.json({ token, user: sanitize(user) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── ME ──
app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const acts = await db.execute({ sql: 'SELECT * FROM pila_activity WHERE userId=? ORDER BY createdAt DESC LIMIT 30', args: [user.id] })
    const reqs = await db.execute({ sql: 'SELECT * FROM pila_friend_requests WHERE toId=? AND status=?', args: [user.id, 'pending'] })
    const pendingRequests = await Promise.all(reqs.rows.map(async r => {
      const from = await getUser(r.fromId)
      return { id: r.id, from: from ? { id: from.id, name: from.name } : null }
    }))
    const unreadRes = await db.execute({ sql: 'SELECT COUNT(*) as c FROM pila_notifications WHERE userId=? AND read=0', args: [user.id] })
    res.json({ user: sanitize(user), activity: acts.rows, pendingRequests, unreadNotifs: Number(unreadRes.rows[0].c) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── SELF LOG CLASS ──
app.post('/api/self-log', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const { classType, studio, notes } = req.body
    const pts = 50
    user.points += pts; user.totalClasses += 1
    const now = new Date()
    const todayStr = now.toISOString().split('T')[0]
    if (!user.classDates.includes(todayStr)) user.classDates.push(todayStr)
    user.lastClassDate = now.toISOString()
    const weekNum = Math.floor(now.getTime()/(7*24*60*60*1000))
    if (user.lastClassWeek === weekNum-1) user.currentStreak = (user.currentStreak||0)+1
    else if (user.lastClassWeek !== weekNum) user.currentStreak = 1
    user.lastClassWeek = weekNum
    user.longestStreak = Math.max(user.longestStreak||0, user.currentStreak)
    const newMilestones = checkMilestones(user)
    await saveUser(user)
    const label = classType + (studio ? ' · ' + studio : '') + (notes ? ' — ' + notes : '')
    await db.execute({ sql: 'INSERT INTO pila_activity (id,userId,type,label,points,createdAt) VALUES (?,?,?,?,?,?)', args: [uuidv4(), user.id, 'class', label, pts, now.toISOString()] })
    const entry = { type: 'class', label, points: pts, createdAt: now.toISOString() }
    if (newMilestones.length) {
      await addNotif(user.id, 'milestone', `🎉 You hit ${newMilestones[0]} classes!`, 'PILA')
      for (const fid of user.friends) await addNotif(fid, 'friend_milestone', `${user.name} just hit ${newMilestones[0]} classes! 🎉`, user.name)
    }
    res.json({ user: sanitize(user), entry, newMilestones })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── MOOD ──
app.post('/api/mood', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    user.moodHistory.push({ score: req.body.score, note: req.body.note||'', date: new Date().toISOString() })
    await saveUser(user)
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── POSTS ──
app.post('/api/posts', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const { caption, imageData, visibility, classType } = req.body
    const post = { id: uuidv4(), userId: req.user.id, userName: user.name,
      caption: caption||'', imageData: imageData||null, visibility: visibility||'friends',
      classType: classType||null,
      userStats: JSON.stringify({ totalClasses: user.totalClasses, currentStreak: user.currentStreak||0, points: user.points }),
      likes: '[]', comments: '[]', createdAt: new Date().toISOString() }
    await db.execute({ sql: 'INSERT INTO pila_posts (id,userId,userName,caption,imageData,visibility,classType,userStats,likes,comments,createdAt) VALUES (?,?,?,?,?,?,?,?,?,?,?)', args: [post.id,post.userId,post.userName,post.caption,post.imageData,post.visibility,post.classType,post.userStats,post.likes,post.comments,post.createdAt] })
    for (const fid of user.friends) await addNotif(fid, 'post', `${user.name} posted a new moment ✦`, user.name)
    res.json({ post: { ...post, userStats: JSON.parse(post.userStats), likes: [], comments: [] } })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/posts/feed', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const friends = user.friends
    let rows = []
    if (friends.length > 0) {
      const ph = friends.map(()=>'?').join(',')
      const r = await db.execute({ sql: `SELECT * FROM pila_posts WHERE userId=? OR (userId IN (${ph}) AND visibility='friends') ORDER BY createdAt DESC LIMIT 30`, args: [req.user.id, ...friends] })
      rows = r.rows
    } else {
      const r = await db.execute({ sql: 'SELECT * FROM pila_posts WHERE userId=? ORDER BY createdAt DESC LIMIT 30', args: [req.user.id] })
      rows = r.rows
    }
    res.json(rows.map(p => ({ ...p, userStats: JSON.parse(p.userStats||'{}'), likes: JSON.parse(p.likes||'[]'), comments: JSON.parse(p.comments||'[]') })))
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/posts/:id/like', auth, async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT * FROM pila_posts WHERE id=?', args: [req.params.id] })
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' })
    const post = r.rows[0]; const likes = JSON.parse(post.likes||'[]')
    const idx = likes.indexOf(req.user.id)
    if (idx > -1) likes.splice(idx,1)
    else { likes.push(req.user.id); if (post.userId !== req.user.id) { const liker = await getUser(req.user.id); await addNotif(post.userId,'like',`${liker?.name||'Someone'} liked your post ❤️`,liker?.name) } }
    await db.execute({ sql: 'UPDATE pila_posts SET likes=? WHERE id=?', args: [JSON.stringify(likes), req.params.id] })
    res.json({ likes: likes.length, liked: likes.includes(req.user.id) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/posts/:id/comment', auth, async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT * FROM pila_posts WHERE id=?', args: [req.params.id] })
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' })
    const post = r.rows[0]; const user = await getUser(req.user.id)
    const comments = JSON.parse(post.comments||'[]')
    const comment = { id: uuidv4(), userId: req.user.id, userName: user?.name||'', text: req.body.text, createdAt: new Date().toISOString() }
    comments.push(comment)
    await db.execute({ sql: 'UPDATE pila_posts SET comments=? WHERE id=?', args: [JSON.stringify(comments), req.params.id] })
    if (post.userId !== req.user.id) await addNotif(post.userId,'comment',`${user?.name||'Someone'} commented: "${req.body.text.slice(0,40)}"`,user?.name)
    res.json({ comment })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── FRIENDS ──
app.post('/api/friends/request', auth, async (req, res) => {
  try {
    const toUser = await getUserByEmail(req.body.toEmail)
    if (!toUser) return res.status(404).json({ error: 'No user with that email' })
    if (toUser.id === req.user.id) return res.status(400).json({ error: "Can't add yourself" })
    const me = await getUser(req.user.id)
    if ((me.friends||[]).includes(toUser.id)) return res.status(400).json({ error: 'Already friends' })
    const ex = await db.execute({ sql: 'SELECT * FROM pila_friend_requests WHERE fromId=? AND toId=? AND status=?', args: [req.user.id, toUser.id, 'pending'] })
    if (ex.rows.length) return res.status(400).json({ error: 'Request already sent' })
    await db.execute({ sql: 'INSERT INTO pila_friend_requests (id,fromId,toId,status,createdAt) VALUES (?,?,?,?,?)', args: [uuidv4(), req.user.id, toUser.id, 'pending', new Date().toISOString()] })
    await addNotif(toUser.id, 'friend_request', `${me.name} wants to be friends on PILA 👋`, me.name)
    res.json({ success: true, toName: toUser.name })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/friends/respond', auth, async (req, res) => {
  try {
    const { requestId, accept } = req.body
    const r = await db.execute({ sql: 'SELECT * FROM pila_friend_requests WHERE id=? AND toId=?', args: [requestId, req.user.id] })
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' })
    await db.execute({ sql: 'UPDATE pila_friend_requests SET status=? WHERE id=?', args: [accept?'accepted':'declined', requestId] })
    if (accept) {
      const me = await getUser(req.user.id); const them = await getUser(r.rows[0].fromId)
      if (me && them) {
        me.friends = [...new Set([...me.friends, them.id])]; them.friends = [...new Set([...them.friends, me.id])]
        await saveUser(me); await saveUser(them)
        await addNotif(them.id, 'friend_accept', `${me.name} accepted your friend request 🎉`, me.name)
      }
    }
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/friends', auth, async (req, res) => {
  try {
    const me = await getUser(req.user.id)
    if (!me) return res.status(404).json({ error: 'Not found' })
    const friends = await Promise.all((me.friends||[]).map(async fid => {
      const f = await getUser(fid); if (!f) return null
      const daysSince = f.lastClassDate ? Math.floor((Date.now()-new Date(f.lastClassDate))/(1000*60*60*24)) : null
      return { id:f.id, name:f.name, studio:f.studio||'', points:f.points, totalClasses:f.totalClasses, currentStreak:f.currentStreak||0, longestStreak:f.longestStreak||0, earnedMilestones:f.earnedMilestones||[], daysSince }
    }))
    res.json(friends.filter(Boolean))
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── PROFILE ──
app.get('/api/profile/:id', auth, async (req, res) => {
  try {
    const me = await getUser(req.user.id); const user = await getUser(req.params.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const isFriend = (me?.friends||[]).includes(user.id) || user.id===req.user.id
    const postsRes = await db.execute({ sql: 'SELECT * FROM pila_posts WHERE userId=? ORDER BY createdAt DESC LIMIT 12', args: [user.id] })
    const posts = postsRes.rows.filter(p => isFriend || p.userId===req.user.id).map(p => ({ ...p, userStats: JSON.parse(p.userStats||'{}'), likes: JSON.parse(p.likes||'[]'), comments: JSON.parse(p.comments||'[]') }))
    res.json({ user: sanitize(user), posts, isFriend })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── NOTIFICATIONS ──
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT * FROM pila_notifications WHERE userId=? ORDER BY createdAt DESC LIMIT 20', args: [req.user.id] })
    res.json(r.rows.map(n => ({ ...n, read: Boolean(n.read) })))
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/notifications/read', auth, async (req, res) => {
  try { await db.execute({ sql: 'UPDATE pila_notifications SET read=1 WHERE userId=?', args: [req.user.id] }); res.json({ success: true }) }
  catch(e) { res.status(500).json({ error: e.message }) }
})

app.listen(3000, () => console.log('✦ PILA running → http://localhost:3000'))
