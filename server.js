const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// JWT Authentication Middleware
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'Authentication required. Please provide a valid Bearer token.'
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({
            error: 'Invalid or expired token.'
        });
    }
}

// Role middleware
function requireManager(req, res, next) {
    if (req.user.role === 'manager' || req.user.role === 'admin') {
        return next();
    }

    return res.status(403).json({
        error: 'Forbidden. Manager or admin access required.'
    });
}

function requireAdmin(req, res, next) {
    if (req.user.role === 'admin') {
        return next();
    }

    return res.status(403).json({
        error: 'Forbidden. Admin access required.'
    });
}

// Test database connection
async function testConnection() {
    try {
        await db.authenticate();
        console.log('Connection to database established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}

testConnection();

// AUTH ROUTES

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role = 'employee' } = req.body;

        const allowedRoles = ['employee', 'manager', 'admin'];
        if (!allowedRoles.includes(role)) {
            return res.status(400).json({ error: 'Invalid role provided' });
        }

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: 'User with this email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            role
        });

        const token = jwt.sign(
            {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            }
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    res.json({
        message: 'Logout successful. Since JWT is stateless, remove the token on the client side.'
    });
});

// USER ROUTES

// Get current user profile
app.get('/api/users/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            attributes: ['id', 'name', 'email', 'role']
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

// Admin only: get all users
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: ['id', 'name', 'email', 'role']
        });

        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// PROJECT ROUTES

// Get all projects
app.get('/api/projects', requireAuth, async (req, res) => {
    try {
        const projects = await Project.findAll({
            include: [
                {
                    model: User,
                    as: 'manager',
                    attributes: ['id', 'name', 'email', 'role']
                }
            ]
        });

        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

// Get one project
app.get('/api/projects/:id', requireAuth, async (req, res) => {
    try {
        const project = await Project.findByPk(req.params.id, {
            include: [
                {
                    model: User,
                    as: 'manager',
                    attributes: ['id', 'name', 'email', 'role']
                },
                {
                    model: Task,
                    include: [
                        {
                            model: User,
                            as: 'assignedUser',
                            attributes: ['id', 'name', 'email', 'role']
                        }
                    ]
                }
            ]
        });

        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        res.json(project);
    } catch (error) {
        console.error('Error fetching project:', error);
        res.status(500).json({ error: 'Failed to fetch project' });
    }
});

// Manager or admin: create project
app.post('/api/projects', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description, status = 'active' } = req.body;

        const newProject = await Project.create({
            name,
            description,
            status,
            managerId: req.user.id
        });

        res.status(201).json(newProject);
    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// Manager or admin: update project
app.put('/api/projects/:id', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description, status } = req.body;

        const project = await Project.findByPk(req.params.id);
        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        await project.update({
            name: name ?? project.name,
            description: description ?? project.description,
            status: status ?? project.status
        });

        res.json(project);
    } catch (error) {
        console.error('Error updating project:', error);
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// Admin only: delete project
app.delete('/api/projects/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const deletedRowsCount = await Project.destroy({
            where: { id: req.params.id }
        });

        if (deletedRowsCount === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }

        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Error deleting project:', error);
        res.status(500).json({ error: 'Failed to delete project' });
    }
});

// TASK ROUTES

// Get tasks for a project
app.get('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    try {
        const tasks = await Task.findAll({
            where: { projectId: req.params.id },
            include: [
                {
                    model: User,
                    as: 'assignedUser',
                    attributes: ['id', 'name', 'email', 'role']
                }
            ]
        });

        res.json(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// Manager or admin: create task
app.post('/api/projects/:id/tasks', requireAuth, requireManager, async (req, res) => {
    try {
        const { title, description, assignedUserId, priority = 'medium' } = req.body;

        const project = await Project.findByPk(req.params.id);
        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        const assignedUser = await User.findByPk(assignedUserId);
        if (!assignedUser) {
            return res.status(404).json({ error: 'Assigned user not found' });
        }

        const newTask = await Task.create({
            title,
            description,
            projectId: req.params.id,
            assignedUserId,
            priority,
            status: 'pending'
        });

        res.status(201).json(newTask);
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// Update task
app.put('/api/tasks/:id', requireAuth, async (req, res) => {
    try {
        const task = await Task.findByPk(req.params.id);

        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }

        // Employees can only update their own tasks
        if (req.user.role === 'employee' && task.assignedUserId !== req.user.id) {
            return res.status(403).json({
                error: 'Forbidden. Employees can only update their own tasks.'
            });
        }

        const { title, description, status, priority } = req.body;

        await task.update({
            title: title ?? task.title,
            description: description ?? task.description,
            status: status ?? task.status,
            priority: priority ?? task.priority
        });

        res.json(task);
    } catch (error) {
        console.error('Error updating task:', error);
        res.status(500).json({ error: 'Failed to update task' });
    }
});

// Manager or admin: delete task
app.delete('/api/tasks/:id', requireAuth, requireManager, async (req, res) => {
    try {
        const deletedRowsCount = await Task.destroy({
            where: { id: req.params.id }
        });

        if (deletedRowsCount === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }

        res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});