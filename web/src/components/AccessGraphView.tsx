import { useState, useEffect, useRef } from 'react';
import { toast } from 'react-hot-toast';
import { GitBranch } from 'lucide-react';
import * as d3 from 'd3';
import { apiClient } from '../services/api';
import type { AccessGraph } from '../types';

export default function AccessGraphView() {
  const [awsAccountId, setAwsAccountId] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [loading, setLoading] = useState(false);
  const [graphData, setGraphData] = useState<AccessGraph | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const handleLoadGraph = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!awsAccountId.trim()) {
      toast.error('Please enter an AWS Account ID');
      return;
    }

    setLoading(true);

    try {
      const data = await apiClient.getAccessGraph(awsAccountId, roleArn || undefined);
      setGraphData(data);
      toast.success('Access graph loaded successfully!');
    } catch (error: any) {
      console.error('Failed to load access graph:', error);
      toast.error(error.response?.data?.detail || 'Failed to load access graph');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (graphData && svgRef.current) {
      renderGraph(graphData);
    }
  }, [graphData]);

  const renderGraph = (data: AccessGraph) => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Get container dimensions
    const container = svgRef.current?.parentElement;
    const width = container?.clientWidth || 1200;
    const height = Math.max(800, data.nodes.length * 30); // Dynamic height based on nodes

    svg
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    // Create main group for zoom/pan
    const g = svg.append('g');

    // Add zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom as any);

    // Create arrow marker for edges
    svg
      .append('defs')
      .append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '-0 -5 10 10')
      .attr('refX', 25)
      .attr('refY', 0)
      .attr('orient', 'auto')
      .attr('markerWidth', 8)
      .attr('markerHeight', 8)
      .append('svg:path')
      .attr('d', 'M 0,-5 L 10 ,0 L 0,5')
      .attr('fill', '#6366f1');

    // Color scale for node types
    const colorScale = d3.scaleOrdinal<string>()
      .domain(['user', 'role', 'policy', 'resource'])
      .range(['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b']);

    // Create simulation with boundaries
    const simulation = d3
      .forceSimulation(data.nodes as any)
      .force('link', d3.forceLink(data.edges).id((d: any) => d.id).distance(150))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(50))
      .force('x', d3.forceX(width / 2).strength(0.1))
      .force('y', d3.forceY(height / 2).strength(0.1));

    // Create edges
    const link = g
      .append('g')
      .selectAll('line')
      .data(data.edges)
      .enter()
      .append('line')
      .attr('stroke', '#6366f1')
      .attr('stroke-opacity', 0.6)
      .attr('stroke-width', 2)
      .attr('marker-end', 'url(#arrowhead)');

    // Create nodes
    const node = g
      .append('g')
      .selectAll('g')
      .data(data.nodes)
      .enter()
      .append('g')
      .call(
        d3.drag<any, any>()
          .on('start', dragstarted)
          .on('drag', dragged)
          .on('end', dragended)
      );

    // Add circles to nodes
    node
      .append('circle')
      .attr('r', 20)
      .attr('fill', (d) => colorScale(d.type))
      .attr('stroke', '#fff')
      .attr('stroke-width', 2);

    // Add labels to nodes
    node
      .append('text')
      .text((d) => d.name)
      .attr('x', 0)
      .attr('y', 35)
      .attr('text-anchor', 'middle')
      .attr('fill', '#e5e7eb')
      .attr('font-size', '12px');

    // Add tooltips
    node.append('title').text((d) => `${d.type}: ${d.name}\n${d.arn || ''}`);

    // Update positions on tick with boundary constraints
    simulation.on('tick', () => {
      // Constrain nodes to stay within bounds
      data.nodes.forEach((d: any) => {
        const radius = 30; // Node radius + padding
        d.x = Math.max(radius, Math.min(width - radius, d.x));
        d.y = Math.max(radius, Math.min(height - radius, d.y));
      });

      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
    });

    function dragstarted(event: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event: any) {
      const radius = 30;
      event.subject.fx = Math.max(radius, Math.min(width - radius, event.x));
      event.subject.fy = Math.max(radius, Math.min(height - radius, event.y));
    }

    function dragended(event: any) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    // Add reset zoom button functionality
    const resetZoom = () => {
      svg.transition().duration(750).call(
        zoom.transform as any,
        d3.zoomIdentity
      );
    };

    // Store reset function for external use
    (svg.node() as any).__resetZoom = resetZoom;
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-2">
          <GitBranch className="text-primary-500" />
          Interactive Access Graph
        </h1>
        <p className="mt-2 text-gray-400">
          Visualize IAM relationships and access paths
        </p>
      </div>

      {/* Form */}
      <div className="card">
        <form onSubmit={handleLoadGraph} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              AWS Account ID *
            </label>
            <input
              type="text"
              value={awsAccountId}
              onChange={(e) => setAwsAccountId(e.target.value)}
              placeholder="123456789012"
              className="input"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Cross-Account Role ARN (Optional)
            </label>
            <input
              type="text"
              value={roleArn}
              onChange={(e) => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/ViewRole"
              className="input"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                Loading Graph...
              </>
            ) : (
              <>
                <GitBranch size={20} />
                Generate Access Graph
              </>
            )}
          </button>
        </form>
      </div>

      {/* Graph Stats */}
      {graphData && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard title="Total Nodes" value={graphData.stats.total_nodes} />
          <StatCard title="Edges" value={graphData.stats.total_edges} />
          <StatCard title="Users" value={graphData.stats.users} />
          <StatCard title="Roles" value={graphData.stats.roles} />
          <StatCard title="Policies" value={graphData.stats.policies} />
        </div>
      )}

      {/* Graph Visualization */}
      {graphData && (
        <div className="card">
          <div className="mb-4 flex items-start justify-between">
            <div>
              <h2 className="text-xl font-bold">Access Graph Visualization</h2>
              <div className="flex gap-4 mt-2 text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-blue-500"></div>
                  <span>Users</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-purple-500"></div>
                  <span>Roles</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-green-500"></div>
                  <span>Policies</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-orange-500"></div>
                  <span>Resources</span>
                </div>
              </div>
            </div>
            <button
              onClick={() => {
                const svg = svgRef.current as any;
                if (svg?.__resetZoom) svg.__resetZoom();
              }}
              className="btn-secondary text-sm"
            >
              Reset View
            </button>
          </div>
          <div className="bg-gray-900 rounded-lg p-4 overflow-auto max-h-[800px]">
            <svg ref={svgRef}></svg>
          </div>
          <div className="text-sm text-gray-500 mt-2 space-y-1">
            <p>• <strong>Drag nodes</strong> to rearrange</p>
            <p>• <strong>Scroll or pinch</strong> to zoom in/out</p>
            <p>• <strong>Click and drag background</strong> to pan</p>
            <p>• <strong>Hover over nodes</strong> for details</p>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ title, value }: { title: string; value: number }) {
  return (
    <div className="card text-center">
      <p className="text-sm text-gray-400">{title}</p>
      <p className="text-2xl font-bold mt-1">{value}</p>
    </div>
  );
}
