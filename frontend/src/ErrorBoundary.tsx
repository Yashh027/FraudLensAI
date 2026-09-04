import { Component, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error('ErrorBoundary caught:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100vh',
            backgroundColor: '#0a0e27',
            color: '#fff',
            flexDirection: 'column',
            gap: '20px',
            padding: '20px',
            fontFamily: 'monospace',
          }}
        >
          <div style={{ fontSize: '18px', fontWeight: 'bold' }}>Application Error</div>
          <div style={{ fontSize: '14px', color: '#aaa', maxWidth: '500px', textAlign: 'center' }}>
            {this.state.error?.message || 'An unexpected error occurred. Please refresh the page.'}
          </div>
          <button
            onClick={() => window.location.reload()}
            style={{
              padding: '10px 20px',
              backgroundColor: '#00bfff',
              color: '#000',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 'bold',
            }}
          >
            Refresh Page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
