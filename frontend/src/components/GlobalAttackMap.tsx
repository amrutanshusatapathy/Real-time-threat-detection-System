import type { ReactNode } from 'react'
import { useMemo } from 'react'
import L from 'leaflet'
import { MapContainer, Marker, Popup, TileLayer } from 'react-leaflet'
import type { ThreatEvent } from '../types'
import { formatDateTime } from '../lib/format'
import { Panel } from './Panel'
import { SeverityPill } from './SeverityPill'

const threatIcon = L.divIcon({
  className: 'threat-div-icon',
  html: '<div class="threat-marker"></div>',
  iconSize: [12, 12],
  iconAnchor: [6, 6],
})

export function GlobalAttackMap(props: { threats: ThreatEvent[] }): ReactNode {
  const { threats } = props

  const points = useMemo(() => {
    return threats.slice(-60).filter((t) => Number.isFinite(t.geo.lat) && Number.isFinite(t.geo.lon))
  }, [threats])

  return (
    <Panel
      title="Global Attack Map"
      subtitle="Latest events plotted by source location"
    >
      <div className="-mx-4 -mb-4 h-[380px] overflow-hidden rounded-b-xl border-t border-cyan-500/10">
        <MapContainer
          center={[20, 0]}
          zoom={2}
          scrollWheelZoom={false}
          className="h-full w-full"
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />

          {points.map((t) => (
            <Marker key={t.id} position={[t.geo.lat, t.geo.lon]} icon={threatIcon}>
              <Popup>
                <div className="min-w-[220px]">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-slate-900">{t.srcIp}</p>
                    <SeverityPill severity={t.severity} />
                  </div>
                  <p className="mt-1 text-xs text-slate-700">
                    {t.type} → {t.target}
                  </p>
                  <p className="mt-1 text-xs text-slate-700">
                    {t.geo.city}, {t.geo.country}
                  </p>
                  <p className="mt-2 text-[11px] text-slate-600">{formatDateTime(t.ts)}</p>
                </div>
              </Popup>
            </Marker>
          ))}
        </MapContainer>
      </div>
    </Panel>
  )
}
