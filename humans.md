# Mobius Developer Guide

Welcome to the Mobius MDM platform! This guide provides orientation for new developers and contributors to help you understand where to make changes and how to navigate the codebase effectively.

## Quick Start

### Prerequisites

- **Go 1.24+** - Backend development
- **Node.js 20.18.1** - Frontend development  
- **Docker & Docker Compose** - Local development environment
- **MySQL 8.0+** - Database
- **Redis 6+** - Caching and sessions
- **Git** - Version control

### Local Development Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/notawar/mobius.git
   cd mobius
   ```

2. **Start dependencies:**

   ```bash
   docker-compose up -d
   ```

3. **Install frontend dependencies:**

   ```bash
   yarn install
   ```

4. **Build and run the server:**

   ```bash
   make generate-dev
   ```

5. **Access the application:**
   - Web UI: <http://localhost:8080>
   - API: <http://localhost:8080/api/v1/>

## Where to Make Changes

### 🎨 Frontend/UI Changes

**Location:** `/frontend/`

- **Components:** `/frontend/components/` - Reusable UI components
- **Pages:** `/frontend/pages/` - Full page components and routing
- **Styles:** Individual component `_styles.scss` files
- **Types:** `/frontend/interfaces/` - TypeScript interfaces
- **Utilities:** `/frontend/utilities/` - Helper functions and constants

**Common tasks:**

- Adding new pages: Create in `/frontend/pages/` and update routing
- Modifying existing UI: Edit component files directly
- Styling changes: Update `_styles.scss` files in component directories
- API integration: Update `/frontend/utilities/endpoints.ts`

### 🔧 Backend/API Changes

**Location:** `/server/`

- **API Endpoints:** `/server/service/` - Business logic and HTTP handlers
- **Database:** `/server/datastore/` - Database operations and queries
- **Authentication:** `/server/auth/` - User authentication and authorization
- **MDM Logic:** `/server/mdm/` - Mobile device management functionality
- **Vulnerabilities:** `/server/vulnerabilities/` - Security scanning

**Common tasks:**

- Adding API endpoints: Create handlers in `/server/service/`
- Database changes: Update schema and add queries in `/server/datastore/`
- New features: Implement in appropriate service layer
- Authentication: Modify `/server/auth/` modules

### 🖥️ Agent (Orbit) Changes

**Location:** `/orbit/`

- **Core Agent:** Main agent functionality
- **Extensions:** Additional capabilities and tables
- **Installers:** Platform-specific packaging

**Common tasks:**

- New agent features: Modify core orbit code
- Platform support: Update build and packaging scripts
- Osquery extensions: Add new tables or modify existing ones

### 🛠️ CLI Tools

**Location:** `/cmd/` and `/tools/`

- **Server Binary:** `/cmd/mobius/` - Main server executable
- **CLI Tool:** `/cmd/mobiuscli/` - Administrative command-line interface
- **Release Tools:** `/tools/release/` - Automated release management
- **Build Tools:** `/tools/` - Various development utilities

### 🌐 Marketing Website

**Location:** `/website/`

- **Pages:** `/website/views/pages/` - Website pages
- **Templates:** `/website/views/layouts/` - Page layouts
- **Assets:** `/website/assets/` - Static files, CSS, JS
- **API:** `/website/api/` - Website backend logic

### 📊 Database Schema

**Location:** `/server/datastore/mysql/schema.sql`

- All database table definitions
- Update this file for schema changes
- Run migrations with `mobius prepare db`

### 🏗️ Infrastructure & Deployment

**Location:** `/charts/`, `/infrastructure/`, `/terraform/`

- **Kubernetes:** `/charts/mobius/` - Helm charts
- **Docker:** `Dockerfile`, `docker-compose.yml`
- **Terraform:** `/terraform/` - Infrastructure as code
- **CI/CD:** `.github/workflows/` - GitHub Actions

## Development Workflow

### Making Changes

1. **Create a feature branch:**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** in the appropriate directories (see above)

3. **Test your changes:**

   ```bash
   # Frontend tests
   yarn test
   
   # Backend tests
   make test
   
   # Linting
   yarn lint
   ```

4. **Commit your changes:**

   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. **Push and create a pull request:**

   ```bash
   git push origin feature/your-feature-name
   ```

### Code Style Guidelines

- **Go:** Follow standard Go conventions, use `gofmt`
- **TypeScript/React:** Use ESLint configuration, prefer functional components
- **CSS:** Use SCSS, follow BEM naming convention where applicable
- **Commits:** Use conventional commit format (`feat:`, `fix:`, `docs:`, etc.)

## Common Development Tasks

### Adding a New API Endpoint

1. **Define the endpoint** in `/server/service/`
2. **Add database queries** in `/server/datastore/mysql/`
3. **Update frontend API client** in `/frontend/utilities/endpoints.ts`
4. **Add TypeScript interfaces** in `/frontend/interfaces/`
5. **Create or update frontend components** as needed

### Adding a New Frontend Page

1. **Create page component** in `/frontend/pages/YourPage/`
2. **Add routing** in `/frontend/router/paths.ts`
3. **Create any new interfaces** in `/frontend/interfaces/`
4. **Add navigation** if needed in layout components
5. **Write tests** in the component directory

### Modifying Database Schema

1. **Update schema** in `/server/datastore/mysql/schema.sql`
2. **Add migration logic** if needed for existing installations
3. **Update Go structs** that represent the data
4. **Update frontend interfaces** that consume the data
5. **Test migrations** thoroughly

### Working with Styles

- **Global styles:** `/frontend/styles/`
- **Component styles:** `ComponentName/_styles.scss` in each component directory
- **Variables:** Use CSS custom properties defined in global styles
- **Colors:** Use Mobius brand colors (#1c2f38, #d4af37)

## Testing

### Frontend Testing

```bash
# Run all tests
yarn test

# Run tests in watch mode
yarn test --watch

# Run specific test file
yarn test ComponentName.test.tsx
```

### Backend Testing

```bash
# Run all tests
make test

# Run specific package tests
go test ./server/service/...

# Run with coverage
make test-coverage
```

### Integration Testing

```bash
# Run full integration tests
make test-integration
```

## Debugging

### Frontend Debugging

- Use browser developer tools
- React DevTools extension
- Console logging with proper log levels
- Redux DevTools for state management

### Backend Debugging

- Use VS Code debugger with Go extension
- Add logging with appropriate levels
- Use `mobius serve --debug` for verbose output
- Check logs in development console

### Database Debugging

- Use MySQL Workbench or command line client
- Check query logs for performance issues
- Validate migrations with test data

## Useful Commands

### Development

```bash
# Start development environment
make generate-dev

# Rebuild frontend assets
yarn build

# Run linting
yarn lint
make lint-go

# Format code
yarn prettier:fix
gofmt -w .
```

### Database

```bash
# Run migrations
mobius prepare db

# Reset database (development only)
mobius prepare db --dev
```

### Building

```bash
# Build all components
make

# Build specific component
make mobius
make frontend
make orbit
```

## Getting Help

### Documentation

- **API Documentation:** Available at `/docs/api/` when server is running
- **Component Storybook:** Run `yarn storybook` for UI component documentation
- **Database Schema:** See `/server/datastore/mysql/schema.sql`

### Community

- **GitHub Issues:** Report bugs and request features
- **GitHub Discussions:** Ask questions and discuss ideas
- **Code Reviews:** All changes go through pull request review

### Internal Resources

- **Handbook:** `/handbook/` - Company processes and guidelines
- **Architecture Docs:** `/docs/` - Technical documentation
- **API Reference:** Generated from code comments

## Best Practices

### Security

- Never commit secrets or API keys
- Use environment variables for configuration
- Validate all inputs from users
- Follow principle of least privilege
- Review security implications of changes

### Performance

- Optimize database queries
- Use proper React patterns (memoization, etc.)
- Minimize bundle size
- Profile before optimizing
- Consider caching strategies

### Maintainability

- Write clear, self-documenting code
- Add tests for new functionality
- Update documentation with changes
- Use consistent naming conventions
- Keep functions and components focused

## Contributing Guidelines

1. **Follow the style guides** for each language/framework
2. **Write tests** for new features and bug fixes
3. **Update documentation** when making user-facing changes
4. **Small, focused commits** with clear commit messages
5. **Responsive code reviews** - review others' work promptly
6. **Consider backward compatibility** for API changes

## Release Process

- Releases follow semantic versioning (v1.x.x)
- Feature development happens on `main` branch
- Release candidates are created from `main`
- Production releases are tagged and deployed automatically
- See `/tools/release/README.md` for detailed release procedures

## Troubleshooting

### Common Issues

- **Build failures:** Check Node.js and Go versions
- **Database connection:** Verify Docker containers are running
- **Port conflicts:** Ensure ports 8080, 3306, 6379 are available
- **Permission issues:** Check file permissions and Docker access

### Getting Unstuck

1. **Check the logs** - they usually tell you what's wrong
2. **Search existing issues** - your problem might be documented
3. **Ask for help** - use GitHub Discussions or team channels
4. **Start fresh** - sometimes a clean rebuild solves mysterious issues

---

Welcome to the Mobius team! This guide should help you get oriented and productive quickly. Don't hesitate to ask questions and contribute improvements to this documentation as you learn the codebase.
