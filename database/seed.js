const bcrypt = require('bcryptjs');
const { db, User, Project, Task } = require('./setup');

async function seedDatabase() {
    try {
        await db.sync({ force: true });

        const hashedPassword = await bcrypt.hash('password123', 10);

        // Create users
        const john = await User.create({
            name: 'John Employee',
            email: 'john@company.com',
            password: hashedPassword,
            role: 'employee'
        });

        const sarah = await User.create({
            name: 'Sarah Manager',
            email: 'sarah@company.com',
            password: hashedPassword,
            role: 'manager'
        });

        const mike = await User.create({
            name: 'Mike Admin',
            email: 'mike@company.com',
            password: hashedPassword,
            role: 'admin'
        });

        // Create projects
        const project1 = await Project.create({
            name: 'Website Redesign',
            description: 'Update company website with new branding',
            status: 'active',
            managerId: sarah.id
        });

        const project2 = await Project.create({
            name: 'Mobile App Launch',
            description: 'Prepare mobile app for public release',
            status: 'active',
            managerId: mike.id
        });

        // Create tasks
        await Task.create({
            title: 'Design homepage mockup',
            description: 'Create homepage wireframe and mockup',
            status: 'pending',
            priority: 'high',
            projectId: project1.id,
            assignedUserId: john.id
        });

        await Task.create({
            title: 'Test login flow',
            description: 'Run QA on user authentication flow',
            status: 'in progress',
            priority: 'medium',
            projectId: project2.id,
            assignedUserId: john.id
        });

        console.log('Database seeded successfully.');
        process.exit(0);
    } catch (error) {
        console.error('Error seeding database:', error);
        process.exit(1);
    }
}

seedDatabase();