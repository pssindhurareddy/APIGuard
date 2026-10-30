import React, { useEffect, useState } from 'react';
import { Target, Scan, Finding, SystemHealth } from './types';
import { api } from './services/api';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { OverviewPage } from './pages/OverviewPage';
import { NewScanPage } from './pages/NewScanPage';
import { TargetsPage } from './pages/TargetsPage';
import { FindingsPage } from './pages/FindingsPage';
import { HistoryPage } from './pages/HistoryPage';
import { ReportsPage } from './pages/ReportsPage';
import { TestLibraryPage } from './pages/TestLibraryPage';
import { SettingsPage } from './pages/SettingsPage';
import { FindingDetailModal } from './components/FindingDetailModal';
import { ScanComparisonModal } from './components/ScanComparisonModal';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('overview');
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [health, setHealth] = useState<SystemHealth | null>(null);

  // Modals state
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [showComparisonModal, setShowComparisonModal] = useState<boolean>(false);

  // Active running scan tracking
  const activeScan = scans.find((s) => s.status === 'RUNNING') || null;

  const refreshData = async () => {
    try {
      const [hData, tData, sData, fData] = await Promise.all([
        api.getHealth().catch(() => null),
        api.getTargets().catch(() => []),
        api.getScans().catch(() => []),
        api.getFindings().catch(() => []),
      ]);
      if (hData) setHealth(hData);
      setTargets(tData);
      setScans(sData);
      setFindings(fData);
    } catch (err) {
      console.error('Failed refreshing data', err);
    }
  };

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleScanCompleted = (scanId: string) => {
    refreshData();
  };

  return (
    <div className="flex h-screen bg-[#0b0f19] text-gray-100 overflow-hidden font-sans">
      {/* Sidebar navigation */}
      <Sidebar currentTab={currentTab} onTabChange={setCurrentTab} />

      {/* Main content viewport */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <TopBar health={health} activeScan={activeScan} />

        <main className="flex-1 overflow-y-auto p-6 md:p-8">
          {currentTab === 'overview' && (
            <OverviewPage
              scans={scans}
              findings={findings}
              targets={targets}
              onNavigate={setCurrentTab}
              onOpenFinding={setSelectedFinding}
              onOpenComparison={() => setShowComparisonModal(true)}
            />
          )}

          {currentTab === 'new-scan' && (
            <NewScanPage
              targets={targets}
              onScanCompleted={handleScanCompleted}
              onOpenFinding={setSelectedFinding}
            />
          )}

          {currentTab === 'targets' && (
            <TargetsPage targets={targets} onRefresh={refreshData} />
          )}

          {currentTab === 'findings' && (
            <FindingsPage findings={findings} onOpenFinding={setSelectedFinding} />
          )}

          {currentTab === 'history' && (
            <HistoryPage
              scans={scans}
              onOpenScanDetails={(id) => setCurrentTab('reports')}
              onOpenComparison={() => setShowComparisonModal(true)}
            />
          )}

          {currentTab === 'reports' && <ReportsPage scans={scans} />}

          {currentTab === 'test-library' && <TestLibraryPage />}

          {currentTab === 'settings' && <SettingsPage health={health} />}
        </main>
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusUpdated={refreshData}
        />
      )}

      {/* Scan Comparison Modal */}
      {showComparisonModal && (
        <ScanComparisonModal
          scans={scans}
          onClose={() => setShowComparisonModal(false)}
        />
      )}
    </div>
  );
};

export default App;

