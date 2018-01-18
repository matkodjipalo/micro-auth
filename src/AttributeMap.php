<?php

declare(strict_types=1);

/**
 * balloon
 *
 * @copyright   Copryright (c) 2012-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     GPL-3.0 https://opensource.org/licenses/GPL-3.0
 */

namespace Micro\Auth;

use Psr\Log\LoggerInterface as Logger;

class AttributeMap implements AttributeMapInterface
{
    /**
     * Attribute map.
     *
     * @var iterable
     */
    protected $map = [];

    /**
     * Logger.
     *
     * @var Logger
     */
    protected $logger;

    /**
     * Initialize.
     *
     * @param iterable $map
     * @param Logger   $logger
     */
    public function __construct(Iterable $map, Logger $logger)
    {
        $this->logger = $logger;
        $this->map = $map;
    }

    /**
     * {@inheritDoc}
     */
    public function getAttributeMap(): Iterable
    {
        return $this->map;
    }

    /**
     * {@inheritDoc}
     */
    public function map(array $data): array
    {
        $attrs = [];
        foreach ($this->map as $attr => $value) {
            if (array_key_exists($value['attr'], $data)) {
                $this->logger->info('found attribute mapping ['.$attr.'] => [('.$value['type'].') '.$value['attr'].']', [
                    'category' => get_class($this),
                ]);

                if ('array' === $value['type']) {
                    $store = $data[$value['attr']];
                } else {
                    $store = $data[$value['attr']];
                    if (is_array($store)) {
                        $store = $store[0];
                    }
                }

                switch ($value['type']) {
                    case 'array':
                        $arr = (array) $data[$value['attr']];
                        unset($arr['count']);
                        $attrs[$attr] = $arr;

                    break;
                    case 'string':
                         $attrs[$attr] = (string) $store;

                    break;
                    case 'int':
                         $attrs[$attr] = (int) $store;

                    break;
                    case 'bool':
                         $attrs[$attr] = (bool) $store;

                    break;
                    default:
                        $this->logger->error('unknown attribute type ['.$value['type'].'] for attribute ['.$attr.']; use one of [array,string,int,bool]', [
                            'category' => get_class($this),
                        ]);

                    break;
                }
            } else {
                $this->logger->warning('auth attribute ['.$value['attr'].'] was not found from authentication adapter response', [
                    'category' => get_class($this),
                ]);
            }
        }

        return $attrs;
    }
}
