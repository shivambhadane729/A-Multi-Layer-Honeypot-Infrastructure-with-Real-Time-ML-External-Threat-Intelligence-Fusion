# Kibana T-Pot Dashboard Replica

This is an exact replica of the Kibana T-Pot honeypot dashboard built with modern React development tools.

## Features

- **Exact Kibana UI/UX**: Replicates the dark theme, layout, and styling of the original Kibana dashboard
- **Interactive Charts**: Multiple chart types including bar charts, line charts, and doughnut charts
- **Real-time Data**: Simulated honeypot attack data with realistic numbers
- **Responsive Design**: Adapts to different screen sizes
- **Modern React**: Built with React 18, Chart.js, and modern web development practices

## Dashboard Components

### Main Statistics
- **Total Honeypot Attacks**: 20,896 attacks
- **Individual Honeypot Stats**: 10 different honeypot types with attack counts
  - Honeytrap: 12,941 attacks
  - Cowrie: 5,209 attacks
  - Ddospot: 1,233 attacks
  - And 7 more honeypot types

### Chart Visualizations
1. **Honeypot Attacks Bar Chart** - Horizontal bar chart showing attack distribution
2. **Honeypot Attacks Histogram** - Line chart with attacks and unique IPs over time
3. **Attack Map** - World map visualization with activity indicators
4. **Attacks by Destination Port** - Bar chart showing port-based attacks
5. **Attacks by Honeypot Histogram** - Multi-line chart for different honeypot types
6. **Attacks by Country Histogram** - Multi-line chart for country-based attacks
7. **Attacker Src IP Reputation** - Doughnut chart for threat classification
8. **Attacks by Honeypot** - Doughnut chart for honeypot distribution
9. **PoF OS Distribution** - Doughnut chart for operating system distribution
10. **Attacks by Country** - Doughnut chart for country distribution

## Installation

### Prerequisites
- Node.js (version 14 or higher)
- npm or yarn

### Setup
1. Navigate to the project directory:
   ```bash
   cd db1
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

4. Open your browser and go to `http://localhost:3000`

## Available Scripts

- `npm start` - Runs the app in development mode
- `npm build` - Builds the app for production
- `npm test` - Launches the test runner
- `npm eject` - Ejects from Create React App (one-way operation)

## Technologies Used

- **React 18** - Modern React with hooks
- **Chart.js** - Interactive charts and graphs
- **React Chart.js 2** - React wrapper for Chart.js
- **CSS3** - Custom styling to match Kibana theme
- **Create React App** - Development environment

## Project Structure

```
db1/
├── public/
│   └── index.html
├── src/
│   ├── App.js          # Main dashboard component
│   ├── App.css         # Dashboard-specific styles
│   ├── index.js        # React entry point
│   └── index.css       # Global styles
├── package.json        # Dependencies and scripts
└── README.md          # This file
```

## Customization

The dashboard uses dummy data that can be easily replaced with real data sources:

- Modify the `dummyData` object in `App.js` to change the data
- Update chart configurations in the chart options objects
- Customize colors and styling in the CSS files
- Add new chart types by extending the existing chart components

## Browser Support

This dashboard works in all modern browsers:
- Chrome (recommended)
- Firefox
- Safari
- Edge

## License

This project is for educational and demonstration purposes.
