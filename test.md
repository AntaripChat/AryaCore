Here are the **step-by-step instructions** to upload to npm (no code):

## Step 1: Create npm Account
- Go to [npmjs.com](https://npmjs.com)
- Click "Sign Up"
- Create your account
- Verify your email

## Step 2: Prepare Your Project
```bash
# Create project folder
mkdir arya-core
cd arya-core

# Initialize npm
npm init
```
- Fill in the details (name, version, description, etc.)

## Step 3: Login to npm
```bash
# Login to npm from terminal
npm login
```
- Enter your username
- Enter your password  
- Enter your email
- Enter OTP (if 2FA enabled)

## Step 4: Build Your Package
```bash
# Install dependencies
npm install

# Build your project (if needed)
npm run build
```

## Step 5: Test Locally (Optional)
```bash
# Create a test package locally
npm pack
```
- This creates a `.tgz` file to test installation

## Step 6: Publish to npm
```bash
# Publish your package
npm publish
```

## Step 7: Verify Publication
- Go to `https://npmjs.com/package/arya-core`
- Check if your package appears

## Step 8: Update Version (For Future Updates)
```bash
# For patch updates (bug fixes)
npm version patch
npm publish

# For minor updates (new features)
npm version minor
npm publish

# For major updates (breaking changes)
npm version major
npm publish
```

## Important Notes:
- Package name must be **unique** on npm
- Don't publish sensitive data
- Update version before each publish
- Use `npm unpublish` if you need to remove (within 72 hours)

That's it! Your package will be live on npm for everyone to use with `npm install arya-core`.
