import { createContext, useContext, useState } from 'react'
import type { ReactNode } from 'react'

import type { ApiConsoleGnbInfoPost200Response } from '../api'

interface GnbConnection {
  ip: string
  port: number
}

export interface GnbWithConnection extends ApiConsoleGnbInfoPost200Response {
  connection?: GnbConnection
  status: 'online' | 'offline'
}

interface GnbContextType {
  gnbList: GnbWithConnection[]
  addGnb: (gnb: ApiConsoleGnbInfoPost200Response, connection: GnbConnection) => { exists: boolean }
  removeGnb: (gnbId: string) => void
  setGnbStatus: (gnbId: string, status: 'online' | 'offline') => void
  updateUeNrdcIndicator: (gnbId: string, imsi: string, indicator: boolean) => void
}

const GnbContext = createContext<GnbContextType | undefined>(undefined)

const GNB_STORAGE_KEY = 'gnbList'

function loadGnbList(): GnbWithConnection[] {
  const stored = localStorage.getItem(GNB_STORAGE_KEY)
  return stored ? JSON.parse(stored) : []
}

export function GnbProvider({ children }: { children: ReactNode }) {
  const [gnbList, setGnbList] = useState<GnbWithConnection[]>(loadGnbList())

  const addGnb = (gnb: ApiConsoleGnbInfoPost200Response, connection: GnbConnection) => {
    const existsInSnapshot = gnbList.findIndex(item => 
      item.gnbInfo?.gnbId === gnb.gnbInfo?.gnbId ||
      (item.connection?.ip === connection.ip && item.connection?.port === connection.port)
    ) !== -1

    setGnbList(prev => {
      const existingIndex = prev.findIndex(item => 
        item.gnbInfo?.gnbId === gnb.gnbInfo?.gnbId ||
        (item.connection?.ip === connection.ip && item.connection?.port === connection.port)
      )
      let nextList: GnbWithConnection[]
      if (existingIndex !== -1) {
        nextList = [...prev]
        nextList[existingIndex] = { ...gnb, connection, status: 'online' as const }
      } else {
        nextList = [...prev, { ...gnb, connection, status: 'online' as const }]
      }
      localStorage.setItem(GNB_STORAGE_KEY, JSON.stringify(nextList))
      return nextList
    })

    return { exists: existsInSnapshot }
  }

  const removeGnb = (gnbId: string) => {
    setGnbList(prev => {
      const nextList = prev.filter(gnb => gnb.gnbInfo?.gnbId !== gnbId)
      localStorage.setItem(GNB_STORAGE_KEY, JSON.stringify(nextList))
      return nextList
    })
  }

  const setGnbStatus = (gnbId: string, status: 'online' | 'offline') => {
    setGnbList(prev => {
      const existingIndex = prev.findIndex(item => item.gnbInfo?.gnbId === gnbId)
      if (existingIndex === -1) return prev
      const nextList = [...prev]
      nextList[existingIndex] = { ...prev[existingIndex], status }
      localStorage.setItem(GNB_STORAGE_KEY, JSON.stringify(nextList))
      return nextList
    })
  }

  const updateUeNrdcIndicator = (gnbId: string, imsi: string, indicator: boolean) => {
    setGnbList(prev => {
      const nextList = prev.map(gnb => {
        if (gnb.gnbInfo?.gnbId === gnbId) {
          return {
            ...gnb,
            gnbInfo: {
              ...gnb.gnbInfo,
              ranUeList: gnb.gnbInfo.ranUeList?.map(ue => 
                ue.imsi === imsi 
                  ? { ...ue, nrdcIndicator: indicator }
                  : ue
              )
            }
          }
        }
        return gnb
      })
      localStorage.setItem(GNB_STORAGE_KEY, JSON.stringify(nextList))
      return nextList
    })
  }

  return (
    <GnbContext.Provider value={{ gnbList, addGnb, removeGnb, updateUeNrdcIndicator, setGnbStatus }}>
      {children}
    </GnbContext.Provider>
  )
}

export function useGnb() {
  const context = useContext(GnbContext)
  if (context === undefined) {
    throw new Error('useGnb must be used within a GnbProvider')
  }
  return context
}
