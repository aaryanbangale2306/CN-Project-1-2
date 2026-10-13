import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  Network, 
  Eye, 
  RefreshCw, 
  RotateCcw, 
  Radio, 
  Filter, 
  Layers, 
  ShieldAlert, 
  CheckCircle,
  BarChart3,
  SlidersHorizontal,
  Flame
} from 'lucide-react';
import { getGraphData } from '../services/apiClient.js';

const CLASS_COLORS = {
  Benign: '#10b981',       // Emerald
  DoS: '#f59e0b',          // Amber
  DDoS: '#ef4444',         // Red
  PortScan: '#8b5cf6',     // Purple
  Botnet: '#ec4899',       // Pink
  BruteForce: '#f97316',   // Orange
  'Other attack': '#06b6d4'// Cyan
};

export default function GraphPage() {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [selectedItem, setSelectedItem] = useState(null);
  const [graphMeta, setGraphMeta] = useState({ nodes: 0, edges: 0, period: 'Live Monitored Traffic', window_id: 18 });
  const [liveEdgesCount, setLiveEdgesCount] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [filterClass, setFilterClass] = useState('ALL');
  const [availableWindows, setAvailableWindows] = useState([]);
  const [selectedWindowIdx, setSelectedWindowIdx] = useState(2);
  const [classBreakdown, setClassBreakdown] = useState({});

  const fetchGraphData = (windowIdx = null) => {
    setRefreshing(true);
    getGraphData(windowIdx)
      .then(graphData => {
        setGraphMeta({
          nodes: graphData.num_nodes || 0,
          edges: graphData.num_edges || 0,
          period: graphData.period || 'Live Monitored Traffic',
          window_id: graphData.window_id || 0
        });

        if (graphData.available_windows) {
          setAvailableWindows(graphData.available_windows);
        }
        if (graphData.window_idx !== undefined) {
          setSelectedWindowIdx(graphData.window_idx);
        }
        if (graphData.class_breakdown) {
          setClassBreakdown(graphData.class_breakdown);
        }

        const liveEdges = (graphData.elements || []).filter(e => e.data && e.data.id && e.data.id.startsWith('edge_live_'));
        setLiveEdgesCount(liveEdges.length);

        if (containerRef.current) {
          if (cyRef.current) {
            cyRef.current.destroy();
          }

          const cy = cytoscape({
            container: containerRef.current,
            elements: graphData.elements || [],
            style: [
              {
                selector: 'node',
                style: {
                  'background-color': ele => ele.data('is_attacker') ? '#f43f5e' : (ele.data('is_target') ? '#f59e0b' : '#4f46e5'),
                  'label': 'data(label)',
                  'color': '#cbd5e1',
                  'font-size': '10px',
                  'font-weight': 600,
                  'text-valign': 'bottom',
                  'text-margin-y': 6,
                  'width': ele => Math.min(48, Math.max(24, 24 + (ele.data('degree') || 1) * 2.5)),
                  'height': ele => Math.min(48, Math.max(24, 24 + (ele.data('degree') || 1) * 2.5)),
                  'border-width': ele => ele.data('is_live') ? 3 : 2,
                  'border-color': ele => ele.data('is_live') ? '#38bdf8' : (ele.data('is_attacker') ? '#fb7185' : '#818cf8'),
                  'transition-property': 'background-color, border-color, width, height, opacity',
                  'transition-duration': '0.2s'
                }
              },
              {
                selector: 'edge',
                style: {
                  'width': ele => ele.data('id').startsWith('edge_live_') ? 5 : Math.max(2, Math.min(6, (ele.data('confidence') || 0.6) * 4.5)),
                  'line-color': ele => CLASS_COLORS[ele.data('label')] || (ele.data('is_attack') ? '#ef4444' : '#64748b'),
                  'target-arrow-color': ele => CLASS_COLORS[ele.data('label')] || (ele.data('is_attack') ? '#ef4444' : '#64748b'),
                  'target-arrow-shape': 'triangle',
                  'arrow-scale': 1.15,
                  'curve-style': 'bezier',
                  'opacity': 0.9,
                  'label': ele => ele.data('label') ? `${ele.data('label')} (${Math.round((ele.data('confidence') || 0.95) * 100)}%)` : '',
                  'font-size': '8px',
                  'font-weight': 600,
                  'color': '#f8fafc',
                  'text-rotation': 'autorotate',
                  'text-margin-y': -8,
                  'text-background-color': '#0f172a',
                  'text-background-opacity': 0.8,
                  'text-background-padding': '2px',
                  'text-background-shape': 'roundrectangle',
                  'line-style': ele => ele.data('id').startsWith('edge_live_') ? 'dashed' : 'solid',
                  'transition-property': 'opacity, width, line-color',
                  'transition-duration': '0.2s'
                }
              },
              {
                selector: 'edge[id ^= "edge_live_"]',
                style: {
                  'width': 5.5,
                  'line-style': 'dashed',
                  'line-dash-pattern': [6, 3],
                  'opacity': 1.0
                }
              },
              {
                selector: ':selected',
                style: {
                  'border-color': '#f8fafc',
                  'border-width': 4,
                  'line-color': '#38bdf8',
                  'target-arrow-color': '#38bdf8',
                  'width': 6,
                  'opacity': 1.0
                }
              }
            ],
            layout: {
              name: 'cose',
              animate: false,
              nodeRepulsion: 8500,
              idealEdgeLength: 75,
              padding: 24
            }
          });

          cy.on('tap', 'node', (evt) => {
            const node = evt.target;
            const connectedEdges = node.connectedEdges();
            const outgoingAttacks = connectedEdges.filter(e => e.data('source') === node.id() && e.data('is_attack')).length;
            const incomingAttacks = connectedEdges.filter(e => e.data('target') === node.id() && e.data('is_attack')).length;

            setSelectedItem({
              type: 'Node (Host)',
              id: node.id(),
              label: node.data('label'),
              degree: node.degree(),
              is_attacker: node.data('is_attacker'),
              is_target: node.data('is_target'),
              is_live: node.data('is_live'),
              outgoingAttacks,
              incomingAttacks,
              totalConnectedFlows: connectedEdges.length
            });
          });

          cy.on('tap', 'edge', (evt) => {
            const edge = evt.target;
            setSelectedItem({
              type: 'Edge (Network Flow)',
              id: edge.id(),
              source: edge.data('source'),
              target: edge.data('target'),
              label: edge.data('label'),
              is_attack: edge.data('is_attack'),
              confidence: edge.data('confidence'),
              class_probabilities: edge.data('class_probabilities'),
              dst_port: edge.data('dst_port'),
              duration_ms: edge.data('duration_ms'),
              reason: edge.data('reason'),
              factors: edge.data('factors'),
              timestamp: edge.data('timestamp'),
              is_live: edge.id().startsWith('edge_live_')
            });
          });

          cyRef.current = cy;
        }
      })
      .catch(console.error)
      .finally(() => setRefreshing(false));
  };

  useEffect(() => {
    fetchGraphData(selectedWindowIdx);
    // Auto poll live graph every 4 seconds to pick up new classifications
    const interval = setInterval(() => {
      fetch('http://localhost:8000/graph')
        .then(res => res.json())
        .then(data => {
          setGraphMeta({
            nodes: data.num_nodes || 0,
            edges: data.num_edges || 0,
            period: data.period || 'Live Monitored Traffic',
            window_id: data.window_id || 0
          });
          if (data.class_breakdown) setClassBreakdown(data.class_breakdown);
          const liveEdges = (data.elements || []).filter(e => e.data && e.data.id && e.data.id.startsWith('edge_live_'));
          setLiveEdgesCount(liveEdges.length);
        })
        .catch(console.error);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  // Update Cytoscape filtering when filterClass changes
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    if (filterClass === 'ALL') {
      cy.elements().style('opacity', 1.0);
    } else {
      cy.batch(() => {
        cy.edges().forEach(edge => {
          if (edge.data('label') === filterClass) {
            edge.style('opacity', 1.0);
            edge.style('width', 5);
          } else {
            edge.style('opacity', 0.12);
            edge.style('width', 1.5);
          }
        });
      });
    }
  }, [filterClass]);

  const handleResetGraph = async () => {
    try {
      await fetch('http://localhost:8000/graph/reset', { method: 'POST' });
      fetchGraphData(2);
    } catch (e) {
      console.error(e);
    }
  };

  const handleWindowChange = (e) => {
    const idx = parseInt(e.target.value);
    setSelectedWindowIdx(idx);
    fetchGraphData(idx);
  };

  const handleZoomIn = () => cyRef.current && cyRef.current.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current && cyRef.current.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current && cyRef.current.fit(30);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', height: 'calc(100vh - 5.5rem)' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h1 style={{ fontSize: '1.85rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.3rem' }}>
            Live Network Graph Topology
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.925rem' }}>
            100% Classifier-Driven Directed Multigraph: Edge colors, widths, labels & roles computed by Machine Learning
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Window Preset Selector */}
          {availableWindows.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(255,255,255,0.05)', padding: '0.3rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <Layers size={14} color="#818cf8" />
              <select 
                value={selectedWindowIdx}
                onChange={handleWindowChange}
                style={{ background: 'transparent', border: 'none', color: '#f8fafc', fontSize: '0.8rem', cursor: 'pointer', outline: 'none' }}
              >
                {availableWindows.map(w => (
                  <option key={w.index} value={w.index} style={{ background: '#0f172a', color: '#fff' }}>
                    {w.label}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="badge badge-info" style={{ padding: '0.4rem 0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Radio size={13} className="animate-pulse" />
            {graphMeta.nodes} Hosts, {graphMeta.edges} Flows ({liveEdgesCount} live injected)
          </div>

          <button 
            onClick={() => fetchGraphData(selectedWindowIdx)} 
            disabled={refreshing}
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(255,255,255,0.06)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '0.4rem 0.75rem', color: '#fff', fontSize: '0.8rem', cursor: 'pointer' }}
            title="Refresh graph from backend"
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
            Refresh
          </button>

          <button 
            onClick={handleResetGraph} 
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', padding: '0.4rem 0.75rem', color: '#fca5a5', fontSize: '0.8rem', cursor: 'pointer' }}
            title="Reset to default baseline window"
          >
            <RotateCcw size={14} />
            Reset
          </button>
        </div>
      </div>

      {/* Filter Toolbar: Filter edges by Classifier Prediction */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(255,255,255,0.03)', padding: '0.5rem 0.85rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', overflowX: 'auto' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <Filter size={13} /> CLASSIFIER FILTER:
        </span>
        <button 
          onClick={() => setFilterClass('ALL')}
          style={{ 
            fontSize: '0.75rem', 
            padding: '0.25rem 0.65rem', 
            borderRadius: '5px', 
            border: filterClass === 'ALL' ? '1px solid #6366f1' : '1px solid transparent',
            background: filterClass === 'ALL' ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255,255,255,0.04)',
            color: filterClass === 'ALL' ? '#fff' : 'var(--text-muted)',
            cursor: 'pointer'
          }}
        >
          All Classes ({graphMeta.edges})
        </button>
        {Object.entries(CLASS_COLORS).map(([cls, color]) => {
          const count = classBreakdown[cls] || 0;
          const isSelected = filterClass === cls;
          return (
            <button 
              key={cls}
              onClick={() => setFilterClass(cls)}
              style={{ 
                fontSize: '0.75rem', 
                padding: '0.25rem 0.65rem', 
                borderRadius: '5px', 
                border: isSelected ? `1px solid ${color}` : '1px solid transparent',
                background: isSelected ? `${color}33` : 'rgba(255,255,255,0.04)',
                color: isSelected ? '#fff' : (count > 0 ? '#cbd5e1' : 'var(--text-muted)'),
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                cursor: 'pointer'
              }}
            >
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: color }} />
              {cls} {count > 0 ? `(${count})` : ''}
            </button>
          );
        })}
      </div>

      {/* Main View Area */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '1.25rem', flex: 1, minHeight: 0 }}>
        {/* Graph Canvas */}
        <div className="glass-panel" style={{ position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          {/* Controls Overlay */}
          <div style={{ position: 'absolute', top: 16, right: 16, zIndex: 10, display: 'flex', gap: '0.5rem', background: 'rgba(15, 23, 42, 0.85)', padding: '0.4rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', backdropFilter: 'blur(8px)' }}>
            <button onClick={handleZoomIn} style={{ background: 'transparent', border: 'none', color: '#fff', cursor: 'pointer', padding: '0.2rem' }} title="Zoom In"><ZoomIn size={18} /></button>
            <button onClick={handleZoomOut} style={{ background: 'transparent', border: 'none', color: '#fff', cursor: 'pointer', padding: '0.2rem' }} title="Zoom Out"><ZoomOut size={18} /></button>
            <button onClick={handleFit} style={{ background: 'transparent', border: 'none', color: '#fff', cursor: 'pointer', padding: '0.2rem' }} title="Fit View"><Maximize2 size={18} /></button>
          </div>

          <div ref={containerRef} style={{ width: '100%', height: '100%' }} />

          {/* Multi-Class Classifier Legend Overlay */}
          <div style={{ position: 'absolute', bottom: 14, left: 14, right: 14, zIndex: 10, background: 'rgba(15, 23, 42, 0.92)', backdropFilter: 'blur(10px)', padding: '0.65rem 1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', display: 'flex', flexWrap: 'wrap', gap: '0.9rem', fontSize: '0.725rem', alignItems: 'center' }}>
            <span style={{ fontWeight: 700, color: 'var(--text-secondary)' }}>CLASSIFIER LABELS:</span>
            {Object.entries(CLASS_COLORS).map(([cls, color]) => (
              <div key={cls} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ width: '12px', height: '3px', background: color, borderRadius: '2px' }} />
                <span style={{ color: '#e2e8f0' }}>{cls}</span>
              </div>
            ))}
            <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.9rem', borderLeft: '1px solid var(--border-subtle)', paddingLeft: '0.9rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f43f5e' }} />
                <span>Attacker Host</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f59e0b' }} />
                <span>Target Host</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ width: '14px', height: '2px', borderTop: '2px dashed #38bdf8' }} />
                <span style={{ color: '#38bdf8' }}>Live Injected</span>
              </div>
            </div>
          </div>
        </div>

        {/* Inspector Panel */}
        <div className="glass-panel" style={{ padding: '1.4rem', display: 'flex', flexDirection: 'column', gap: '1rem', overflowY: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem' }}>
            <Network size={20} color="var(--color-indigo)" />
            <h2 style={{ fontSize: '1.05rem', fontWeight: 600 }}>Topology Inspector</h2>
          </div>

          {selectedItem ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.85rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>ELEMENT TYPE</span>
                <span style={{ fontWeight: 600, color: '#f8fafc' }}>
                  {selectedItem.type} {selectedItem.is_live ? '(⚡ Live Injected)' : '(Baseline Monitored)'}
                </span>
              </div>

              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>ELEMENT ID</span>
                <span className="font-mono" style={{ color: '#818cf8', fontSize: '0.8rem' }}>{selectedItem.id}</span>
              </div>

              {selectedItem.label && (
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>CLASSIFIER PREDICTION</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.2rem' }}>
                    <span 
                      style={{ 
                        fontWeight: 700, 
                        color: CLASS_COLORS[selectedItem.label] || '#f8fafc',
                        background: `${CLASS_COLORS[selectedItem.label] || '#6366f1'}22`,
                        padding: '0.25rem 0.6rem',
                        borderRadius: '6px',
                        border: `1px solid ${CLASS_COLORS[selectedItem.label] || '#6366f1'}55`
                      }}
                    >
                      {selectedItem.label}
                    </span>
                    {selectedItem.is_attack !== undefined && (
                      <span className={selectedItem.is_attack ? 'badge badge-attack' : 'badge badge-benign'} style={{ fontSize: '0.7rem' }}>
                        {selectedItem.is_attack ? 'Malicious' : 'Benign'}
                      </span>
                    )}
                  </div>
                </div>
              )}

              {selectedItem.confidence !== undefined && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                    <span>CLASSIFIER CONFIDENCE</span>
                    <span style={{ color: '#34d399', fontWeight: 700 }}>{(selectedItem.confidence * 100).toFixed(1)}%</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.08)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div 
                      style={{ 
                        width: `${Math.min(100, selectedItem.confidence * 100)}%`, 
                        height: '100%', 
                        background: 'linear-gradient(90deg, #10b981, #34d399)',
                        borderRadius: '3px' 
                      }} 
                    />
                  </div>
                </div>
              )}

              {/* Class Probability Distribution Breakdown from Classifier */}
              {selectedItem.class_probabilities && (
                <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                    MODEL PROBABILITY DISTRIBUTION
                  </span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    {Object.entries(selectedItem.class_probabilities).map(([cls, prob]) => {
                      const pct = (prob * 100).toFixed(1);
                      const isTop = cls === selectedItem.label;
                      return (
                        <div key={cls} style={{ display: 'flex', flexDirection: 'column', gap: '0.1rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem' }}>
                            <span style={{ color: isTop ? '#fff' : 'var(--text-muted)', fontWeight: isTop ? 700 : 400 }}>
                              {cls}
                            </span>
                            <span className="font-mono" style={{ color: isTop ? CLASS_COLORS[cls] || '#34d399' : 'var(--text-muted)' }}>
                              {pct}%
                            </span>
                          </div>
                          <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden' }}>
                            <div 
                              style={{ 
                                width: `${Math.min(100, prob * 100)}%`, 
                                height: '100%', 
                                background: CLASS_COLORS[cls] || '#6366f1',
                                borderRadius: '2px' 
                              }} 
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {selectedItem.dst_port !== undefined && (
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>TARGET SERVICE PORT</span>
                  <span className="font-mono" style={{ fontWeight: 600 }}>Port {selectedItem.dst_port}</span>
                </div>
              )}

              {selectedItem.duration_ms !== undefined && (
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>FLOW DURATION</span>
                  <span className="font-mono">{selectedItem.duration_ms} ms</span>
                </div>
              )}

              {selectedItem.degree !== undefined && (
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>HOST INCIDENT DEGREE</span>
                  <span className="font-mono">{selectedItem.degree} incident flows</span>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                    Outbound Attacks: {selectedItem.outgoingAttacks || 0} | Inbound Attacks: {selectedItem.incomingAttacks || 0}
                  </div>
                </div>
              )}

              {/* Dynamic Classifier Explanation */}
              {selectedItem.reason && (
                <div style={{ background: 'rgba(99, 102, 241, 0.08)', border: '1px solid rgba(99, 102, 241, 0.25)', borderRadius: '8px', padding: '0.75rem' }}>
                  <span style={{ fontSize: '0.7rem', fontWeight: 600, color: '#818cf8', display: 'block', marginBottom: '0.35rem' }}>
                    CLASSIFIER INCIDENT RATIONALE
                  </span>
                  <p style={{ fontSize: '0.775rem', lineHeight: 1.5, color: '#e2e8f0', margin: 0 }}>
                    {selectedItem.reason}
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', textAlign: 'center', gap: '0.5rem' }}>
              <Eye size={28} />
              <p style={{ fontSize: '0.825rem' }}>Click any host node or flow edge in the graph canvas to inspect its real classifier attributes</p>
            </div>
          )}

          <div style={{ marginTop: 'auto', padding: '0.75rem', background: 'rgba(255,255,255,0.03)', borderRadius: '8px', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
            <strong>100% Classifier Output:</strong> Edge classifications, colors, and confidence values are computed directly by the trained Random Forest model.
          </div>
        </div>
      </div>
    </div>
  );
}
