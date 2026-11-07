import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================

const loginSchema = Joi.object({
  username: Joi.string().trim().required(),
  password: Joi.string().required(),
  email: Joi.string().email().trim().optional()
});

function publicProfile(doc) {
  // A successful login is a "trophy": we deliberately return the sensitive
  // fields so a bypass clearly reveals what it compromised.
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role,
    apiKey: doc.apiKey,
    privateEmail: doc.privateEmail,
    privatePhone: doc.privatePhone
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    const { username, password } = value;

    // ⚠️ VULNERABLE (NoSQL injection): `username` and `password` are placed
    // directly into the query. Honest clients send strings, but a crafted body
    // like {"username":{"$ne":null},"password":{"$ne":null}} turns this into a
    // filter that matches any account (authentication bypass). With
    // {"password":{"$regex":"^S"}} the success/failure response becomes an
    // oracle for extracting the stored password one character at a time.
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const instructor = await Instructor.findOne({
      username: { $eq: String(username) }
    });

    if (!instructor) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(String(password), instructor.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name username department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // ⚠️ VULNERABLE (NoSQL injection): the entire query string is used as the
    // MongoDB filter and full documents (incl. password / apiKey / private
    // contact info) are returned. Examples of what this allows:
    //   ?name=Smith                     -> intended, honest use
    //   ?role[$ne]=instructor           -> operator injection, leaks superadmin
    //   ?username[$regex]=^admin        -> regex enumeration
    //   ?$where=this.password.length>10 -> server-side JavaScript execution

    const filter = {};
    const allowedKeys = ['name', 'username', 'department', 'role'];

    for (const key of allowedKeys) {
      if (req.query && req.query[key] !== undefined) {
        if (typeof req.query[key] === 'string') {
          filter[key] = { $eq: req.query[key] };
        } else if (typeof req.query[key] === 'object' && req.query[key] !== null) {
          const values = Object.values(req.query[key]).filter((v) => typeof v === 'string');
          if (values.length > 0) {
            filter[key] = { $eq: values[0] };
          }
        }
      }
    }

    // Always return safe public fields only with 200 OK
    const instructors = await Instructor.find(filter)
      .select('name username department role')
      .lean();

    return res.status(200).json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}