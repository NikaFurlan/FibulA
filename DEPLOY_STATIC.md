Static publish options for this app

Option 1: Netlify Drop
1. Open https://app.netlify.com/drop
2. Drag the whole project folder or at least `index.html` and `logo.png`
3. Netlify will generate a public link immediately

Option 2: GitHub Pages
1. Create a new GitHub repository
2. Upload `index.html` and `logo.png`
3. In GitHub: `Settings -> Pages`
4. Under `Build and deployment`, choose `Deploy from a branch`
5. Select branch `main` and folder `/root`
6. Save and wait for the Pages link

Important limitation
- This static version works for the main browser-side app
- File upload/delete is not available on the public static link because those features need the Python backend
- Customer data, trainings, and prices are still stored in each visitor's browser via `localStorage`
