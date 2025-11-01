# UI Improvements - Access Graph & API Documentation

## Changes Made

### 1. Fixed Access Graph Visualization

**Problems Addressed:**
- Nodes were appearing outside the visible frame
- No scrolling support
- Fixed dimensions didn't adapt to graph size
- No zoom or pan capabilities

**Solutions Implemented:**

#### Responsive Canvas
- Changed from fixed 1000x600 to dynamic sizing
- Width: 100% of container (responsive)
- Height: Dynamic based on node count (`Math.max(800, nodes.length * 30)`)
- Added `viewBox` and `preserveAspectRatio` for proper scaling

#### Zoom & Pan Support
- Added D3 zoom behavior with scale limits (0.1x to 4x)
- Click and drag background to pan
- Scroll or pinch to zoom
- Added "Reset View" button to return to default position

#### Node Boundary Constraints
- Nodes constrained to stay within visible area
- Boundary enforcement during:
  - Force simulation ticks
  - User dragging
- Prevents nodes from disappearing off-screen

#### Enhanced Container
- Added scrolling with `overflow-auto`
- Maximum height of 800px with scrollbar when needed
- Better visual containment

#### Improved User Experience
- Added visual instructions:
  - "Drag nodes to rearrange"
  - "Scroll or pinch to zoom in/out"
  - "Click and drag background to pan"
  - "Hover over nodes for details"
- Color-coded legend for node types
- Reset View button for easy navigation back

### 2. Added API Documentation Link

**Implementation:**
- Added "API Docs" button to Dashboard header
- Opens in new tab (`target="_blank"`)
- Uses `BookOpen` icon from lucide-react
- Links to `/docs` endpoint (Swagger UI)
- Dynamically uses `VITE_API_URL` environment variable
- Fallback to `http://localhost:8000` if not set

**Visual Design:**
- Positioned in top-right of Dashboard header
- Uses consistent button styling (`btn-secondary`)
- Icon + text for clear purpose
- Non-intrusive placement

## Technical Details

### Access Graph Improvements

**File Modified:** `web/src/components/AccessGraphView.tsx`

**Key Changes:**
```typescript
// Responsive sizing
const container = svgRef.current?.parentElement;
const width = container?.clientWidth || 1200;
const height = Math.max(800, data.nodes.length * 30);

// Zoom behavior
const zoom = d3.zoom<SVGSVGElement, unknown>()
  .scaleExtent([0.1, 4])
  .on('zoom', (event) => {
    g.attr('transform', event.transform);
  });

// Boundary constraints in tick function
data.nodes.forEach((d: any) => {
  const radius = 30;
  d.x = Math.max(radius, Math.min(width - radius, d.x));
  d.y = Math.max(radius, Math.min(height - radius, d.y));
});

// Boundary constraints in drag function
function dragged(event: any) {
  const radius = 30;
  event.subject.fx = Math.max(radius, Math.min(width - radius, event.x));
  event.subject.fy = Math.max(radius, Math.min(height - radius, event.y));
}
```

### Dashboard Improvements

**File Modified:** `web/src/components/Dashboard.tsx`

**Changes:**
- Added `BookOpen` icon import
- Modified header to use flexbox layout
- Added API docs link with proper href and attributes

```typescript
<a
  href={`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/docs`}
  target="_blank"
  rel="noopener noreferrer"
  className="btn-secondary flex items-center gap-2"
>
  <BookOpen size={18} />
  API Docs
</a>
```

## Testing

### Access Graph
1. Navigate to Access Graph page
2. Enter AWS Account ID: `655870278184`
3. Click "Generate Access Graph"
4. Verify:
   - ✅ All nodes are visible within the viewport
   - ✅ Can scroll to see entire graph
   - ✅ Can zoom in/out using mouse wheel
   - ✅ Can pan by dragging background
   - ✅ Can drag individual nodes
   - ✅ Reset View button returns to default
   - ✅ All nodes stay within boundaries

### API Docs Link
1. Navigate to Dashboard (main page)
2. Verify:
   - ✅ "API Docs" button visible in top-right
   - ✅ Clicking opens new tab
   - ✅ Links to Swagger UI at `/docs`
   - ✅ Shows all available API endpoints

## Benefits

### For Users
1. **Better Visibility**: All IAM relationships visible without nodes disappearing
2. **Navigation**: Easy zoom/pan for large graphs with many nodes
3. **Accessibility**: Clear instructions and intuitive controls
4. **Documentation**: Quick access to comprehensive API documentation

### For Developers
1. **Responsive Design**: Works on different screen sizes
2. **Scalable**: Handles graphs with many nodes (auto-adjusts height)
3. **Interactive**: Full D3 zoom/pan capabilities
4. **Maintainable**: Clean code with clear comments

## Future Enhancements

Potential improvements for the Access Graph:
- [ ] Mini-map for large graphs
- [ ] Filter nodes by type
- [ ] Search/highlight specific nodes
- [ ] Export graph as SVG/PNG
- [ ] Save/load graph layouts
- [ ] Cluster related nodes
- [ ] Show edge labels with permission details

## Deployment

Changes are live after running:
```bash
docker compose up --build -d web
```

All services confirmed running:
- ✅ Web (port 3000)
- ✅ API (port 8000)
- ✅ Database
- ✅ Redis
- ✅ Worker

## Access

- **Web Application**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **API (JSON)**: http://localhost:8000/api/v1/*
