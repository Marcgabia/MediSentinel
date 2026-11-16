import { dashboardSummary, dashboardCharts, recentActivities, recentAlerts } from '../services/dashboardService.js';
import { hasPermission } from '../middleware/permissions.js';

export const dashboardPage = async (req, res) => {
  const [summary, recent, alerts] = await Promise.all([
    dashboardSummary(),
    hasPermission(req.user, 'audit.view') ? recentActivities(12) : [],
    hasPermission(req.user, 'alerts.view') ? recentAlerts(5) : []
  ]);
  res.render('dashboard/index', { title: 'Dashboard', summary, recent, alerts });
};

export const dashboardChartData = async (req, res) => {
  res.json(await dashboardCharts());
};
